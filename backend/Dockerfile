FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Verify pre-trained ML model loads during build
RUN python -c "from app.ml.predictor import get_ml_predictor; p = get_ml_predictor(); print(f'ML model loaded: {p.model_type}')"

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
