# IoT DoS Detection (Web-Based Demo + Full ML Workflow)

This repository contains an end-to-end IoT DoS detection pipeline:

1. **Training** on UNSW-NB15 (`scripts/train_dos_lgbm.py`)
2. **Evaluation** with 80/20 split and paper-ready plots (`model_evaluation.py`)
3. **Web-based real-time demo** (`web_interface/`)

## Project Structure

- `data/unsw_nb15_train.csv` - training dataset (UNSW-NB15 subset used here)
- `scripts/train_dos_lgbm.py` - train DoS LightGBM model
- `model_evaluation.py` - evaluation script (confusion matrix, ROC, PR, CV, inference benchmark)
- `dos_lightgbm_model.pkl` - trained model artifact
- `results/` - generated metrics/plots for paper
- `web_interface/` - Flask + Socket.IO live dashboard and attack simulation

## Quick Start

### 1) Install dependencies

```bash
pip install -r web_interface/requirements.txt
pip install matplotlib seaborn
```

### 2) Train model

```bash
python scripts/train_dos_lgbm.py
```

### 3) Run evaluation (80/20 split)

```bash
python model_evaluation.py
```

### 4) Start web demo

```bash
cd web_interface
python app.py
```

Open: `http://127.0.0.1:5000`

## Notes

- Detection target: **DoS attacks only**.
- Feature list must stay identical between training and inference.
- `dos_lightgbm_model.pkl` must exist at repository root for the web app config.
