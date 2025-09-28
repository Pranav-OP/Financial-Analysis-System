# 📈 Financial Analysis System

## About the Project
This is a full-stack financial analysis system designed to process complex financial data asynchronously and present the results through a modern, responsive user interface. The system leverages a powerful **Python-based backend (FastAPI)** for computation and a dynamic **React frontend** for visualization with the LLMs.

### 🎥 Video Demo
You can see a live demonstration of the system's functionality here:
[Video Demo on YouTube](https://youtu.be/ycMetWY3AzA)

---

## ✨ Features

* **Asynchronous Processing:** Utilizes **Celery** to offload long-running financial calculations and analysis tasks, ensuring the main API remains responsive.
* **Modern UI/UX:** Built with **React** and **MaterialUI** to provide a clean, intuitive, and mobile-responsive interface.
* **Data Persistence:** Stores and retrieves structured financial data using a **MongoDB** document database.
* **High-Speed Caching:** Employs **Redis** for managing queues for Celery tasks and for high-speed caching of temporary or frequently accessed data.
* **Scalable Backend:** The API is built with **FastAPI** and served by **Uvicorn**, providing high performance and robust data validation.

---

## 💻 Tech Stack

This project is built using a modern, decoupled architecture:

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend Language** | **Python** | Primary development language for backend logic. |
| **API Framework** | **FastAPI** & **Uvicorn** | High-performance API server. |
| **Database** | **MongoDB** | NoSQL database for data storage. |
| **Caching/Broker** | **Redis** | Message broker for Celery and caching (installed via WSL2 on Windows). |
| **Worker** | **Celery** | Distributed task queue for asynchronous jobs. |
| **Frontend Framework** | **React** & **JavaScript** | Library for building the user interface. |
| **Styling** | **MaterialUI** | Component library for polished design. |
| **Dependencies** | `requirements.txt` | Defines all necessary Python packages. |

---

## 🛠️ Installation and Running

Follow these steps to get the Financial Analysis System up and running.

### Step 1: Clone the Repository

Start by cloning the project repository and navigating into the directory:

```bash
git clone [https://github.com/Pranav-OP/Financial-Analysis-System.git](https://github.com/Pranav-OP/Financial-Analysis-System.git)
cd Financial-Analysis-System
```

### Step 2: Backend Setup (Virtual Environment & Dependencies)

This step covers creating the virtual environment and installing backend requirements.

Create Virtual Environment:
```bash
python -m venv venv
```
Activate Virtual Environment (For Windows):
```bash
venv\Scripts\activate
```

Install Python Dependencies:
```bash
pip install -r requirements.txt
```

### Step 3: Start Redis Server
The system requires a running Redis instance. If you are using Windows with WSL2/Ubuntu, run the following commands in your WSL terminal:

Start the Redis Service:
```bash
sudo service redis-server start
```

### Step 4: Run Backend API
Ensure your virtual environment is active. This starts the FastAPI application:
```bash
uvicorn main:app --reload
```

The API is now running, typically at http://127.0.0.1:8000.

### Step 5: Run Celery Worker
Open a NEW terminal window (keep the API terminal running) and activate your virtual environment again. The Celery worker handles background processing:

```bash
celery -A celery_app worker --loglevel=info --pool=solo
```

Step 6: Run Frontend
You will need Node.js and npm installed. Run these commands from the directory containing the package.json file (typically the root or a client/frontend subdirectory—confirm location based on your repo structure):

Install Node Dependencies:
```bash
npm install
```

Start the Frontend Development Server:
```bash
npm run dev
```

The frontend should now be running, likely accessible via http://localhost:3000.
