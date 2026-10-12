setup:
	pip install -r requirements-dev.txt

run-api:
	python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

run-ui:
	python -m streamlit run frontend/app.py

test:
	python -m pytest -q

lint:
	python -m ruff check .

format:
	python -m ruff format .

data:
	@echo "Data pipeline not implemented yet"

train:
	.\.venv\Scripts\python.exe -m backend.training.train --data-dir data/processed --out-dir artifacts/models --metrics-dir artifacts/metrics --version v2 --seeds 42 43 44 45 46

eval:
	.\.venv\Scripts\python.exe -m backend.training.evaluate --data-dir data/processed --model-dir artifacts/models/v2 --metrics-dir artifacts/metrics --figures-dir artifacts/figures

validate-data:
	.\.venv\Scripts\python.exe -m backend.training.validate_dataset --data-dir data/processed

docker-up:
	docker compose up --build

docker-down:
	docker compose down