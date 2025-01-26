package model

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"

	"github.com/owulveryck/onnx-go"
	"github.com/owulveryck/onnx-go/backend/x/gorgonnx"
	"gorgonia.org/tensor"
)

// NormalizeTensor normalizes the tensor data using L2 norm.
func NormalizeTensor(inputTensor *tensor.Dense) (*tensor.Dense, error) {
	data := inputTensor.Data().([]float32) // Extract data from the tensor
	var norm float32

	// Compute the L2 norm
	for _, v := range data {
		norm += v * v
	}
	norm = float32(math.Sqrt(float64(norm)))

	// Avoid division by zero
	if norm == 0 {
		return nil, fmt.Errorf("cannot normalize tensor: L2 norm is zero")
	}

	// Normalize each element
	normalizedData := make([]float32, len(data))
	for i, v := range data {
		normalizedData[i] = v / norm
	}

	// Create a new tensor with the normalized data
	shape := inputTensor.Shape()
	normalizedTensor := tensor.New(tensor.WithShape(shape...), tensor.WithBacking(normalizedData))
	return normalizedTensor, nil
}

func StandardScaleTensor(inputTensor *tensor.Dense, mean, std []float32) (*tensor.Dense, error) {
	data := inputTensor.Data().([]float32) // Extract data from the tensor

	if len(data) != len(mean) || len(data) != len(std) {
		return nil, fmt.Errorf("data, mean, and std must have the same length")
	}

	// Apply scaling
	scaledData := make([]float32, len(data))
	for i := 0; i < len(data); i++ {
		if std[i] == 0 {
			scaledData[i] = data[i] // Avoid division by zero
		} else {
			scaledData[i] = (data[i] - mean[i]) / std[i]
		}
	}

	// Create a new tensor with the scaled data
	shape := inputTensor.Shape()
	scaledTensor := tensor.New(tensor.WithShape(shape...), tensor.WithBacking(scaledData))
	return scaledTensor, nil
}

func loadONNXModel(modelPath string) (*onnx.Model, *gorgonnx.Graph, error) {
	// Create a new backend (using Gorgonia as the backend)
	backend := gorgonnx.NewGraph()

	// Create a new model
	model := onnx.NewModel(backend)

    b, err := os.ReadFile(modelPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read model file: %v", err)
	}

	// Load the ONNX model from the file
	err = model.UnmarshalBinary(b)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load model: %v", err)
	}

	return model, backend, nil
}

func runInference(model *onnx.Model, backend *gorgonnx.Graph, inputTensor *tensor.Dense) (*tensor.Dense, error) {
	// Set the input tensor
	err := model.SetInput(0, inputTensor)
	if err != nil {
		return nil, fmt.Errorf("failed to set input: %v", err)
	}

	// Run the model
	err = backend.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run model: %v", err)
	}

	// Get the output tensor
	outputTensors, err := model.GetOutputTensors()
	if err != nil {
		return nil, fmt.Errorf("failed to get output tensor: %v", err)
	}

	outputTensor, ok := outputTensors[0].(*tensor.Dense)
	if !ok {
		return nil, fmt.Errorf("output tensor is not of type *tensor.Dense")
	}

	return outputTensor, nil
}

func prepareInputTensor(data []float32, shape []int) *tensor.Dense {
	return tensor.New(tensor.WithShape(shape...), tensor.WithBacking(data))
}


func Predict(inputData []float32) {
	// Load the TensorFlow-converted ONNX model
	tfModel, modelBackend, err := loadONNXModel(`E:\FYP\model_training\model-onnx\network_detection_model.onnx`)
	if err != nil {
		log.Fatalf("Failed to load TensorFlow model: %v", err)
	}

	// Load scaler parameters from JSON file
	file, err := os.ReadFile(`E:\FYP\model_training\model-onnx\scaler_params.json`)
	if err != nil {
		log.Fatalf("Failed to read scaler parameters file: %v", err)
	}

	var scalerParams struct {
		Mean  []float32 `json:"mean"`
		Std []float32 `json:"std"`
	}
	err = json.Unmarshal(file, &scalerParams)
	if err != nil {
		log.Fatalf("Failed to parse scaler parameters: %v", err)
	}

	inputTensor := prepareInputTensor(inputData, []int{1, 14}) // Example shape

	normalizedTensor, err := NormalizeTensor(inputTensor)
	if err != nil {
		log.Fatalf("Normalization failed: %v", err)
	}
	
	scaledTensor, err := StandardScaleTensor(normalizedTensor, scalerParams.Mean, scalerParams.Std)
	if err != nil {
		log.Fatalf("Standard Scaling failed: %v", err)
	}

	// Run TensorFlow model inference
	outputTensor, err := runInference(tfModel, modelBackend, scaledTensor)
	if err != nil {
		log.Fatalf("Inference failed: %v", err)
	}

	rawData := outputTensor.Data() // Get raw data as an interface slice
	dataSlice, ok := rawData.([]float32)
	if !ok {
		log.Fatal("Failed to convert tensor data to []float32")
	}

	// Ensure there's at least one value
	if len(dataSlice) < 1 {
		log.Fatal("Tensor data is empty")
	}

	threshold := float32(0.001)
	if dataSlice[0] < threshold {
		fmt.Println("Normal")
	} else {
		fmt.Println("Attack")
	}

}