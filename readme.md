# Machine Learning-Based Intrusion Detection System For Real-Time Network Security

## Project Overview

This project is a Network Intrusion Detection System (NIDS) that aims to detect normal and abnormal network traffic using machine learning models. It consists of three main components:

1. **Model Training**: Contains scripts and requirements for training the machine learning model.
2. **Server**: Implements a Python server for testing.
3. **Traffic Capture and Prediction**: Analyzes captured traffic and provides predictions based on the trained model.

## Languages Used
1. **Python**
2. **GOLang**

## Installation

To set up the project, follow these steps:

1. Clone the repository:

   ```bash
   git clone <repository_url>
   cd project_folder
2. Setting environment
    ```bash
   python -m venv venv
   venv/Scripts/activate
3. Install dependices
    ```bash
   cd model_training
   pip install -r requirements.txt
   cd ../server
   pip install -r requirements.txt
4. Model Training
    ```bash
    Open FYPModel.ipynb and run all cell
5. Model Configuration
    ```bash
    Open the predict.go file located in the capture_traffic_prediction/model folder and configure the paths for 
    your model and scaler parameters.
6. Start the API Server
    ```bash
    Open terminal
    cd server
    uvicorn main:app --reload
7. Run Traffic Capture
    ```bash
    Open a separate terminal 
    cd capture_traffic_predication
    go run main.go
    Then, open your browser and navigate to http://localhost:8000. Finally, check the terminal running 
    the capture script for predictions.
   