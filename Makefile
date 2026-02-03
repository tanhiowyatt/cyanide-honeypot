.PHONY: test run clean install build up down

# Install dependencies
install:
	pip install -r requirements.txt

# Start the honeypot locally
run:
	python3 main.py

# Docker commands
build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

# Specialized cleaning task
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".DS_Store" -delete
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov
	rm -f tests/verification_results.json

# Run all tests
test:
	pytest tests/ -v
