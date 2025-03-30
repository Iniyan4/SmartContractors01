import torch
import pandas as pd
import torch.nn as nn

# Absolute paths
dataset_path = r"dataset.csv"
severity_path = r"Symptom-severity.csv"
precaution_path = r"symptom_precaution.csv"
description_path = r"symptom_Description.csv"

# Load datasets
df = pd.read_csv(dataset_path).fillna("None")
severity_df = pd.read_csv(severity_path)
precaution_df = pd.read_csv(precaution_path)
description_df = pd.read_csv(description_path)

# Load mappings
symptom_columns = [col for col in df.columns if "Symptom" in col]
all_symptoms = sorted(set(df[symptom_columns].values.flatten()) - {"None"})
symptom_to_index = {symptom: i for i, symptom in enumerate(all_symptoms, start=1)}
disease_to_index = {disease: i for i, disease in enumerate(sorted(df["Disease"].unique()))}
index_to_disease = {i: disease for disease, i in disease_to_index.items()}
severity_dict = dict(zip(severity_df["Symptom"], severity_df["weight"]))

def symptoms_to_vector(symptoms):
    vector = [0] * len(symptom_to_index)
    for symptom in symptoms:
        if symptom in symptom_to_index:
            weight = severity_dict.get(symptom, 1)
            vector[symptom_to_index[symptom] - 1] = weight
    return torch.tensor([vector], dtype=torch.float32)

# Model definition
class DiseasePredictor(nn.Module):
    def __init__(self, input_size, output_size):
        super(DiseasePredictor, self).__init__()
        self.fc = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Linear(128, output_size)
        )
    def forward(self, x):
        return self.fc(x)

# Load model
model_path = r"disease_model.pth"
model = DiseasePredictor(len(symptom_to_index), len(disease_to_index))
model.load_state_dict(torch.load(model_path))
model.eval()

def predict_disease(user_symptoms):
    input_vector = symptoms_to_vector(user_symptoms)
    output = model(input_vector)
    predicted_label = torch.argmax(output, dim=1).item()
    predicted_disease = index_to_disease[predicted_label]
    
    description = description_df[description_df["Disease"] == predicted_disease]["Description"].values[0]
    precautions = precaution_df[precaution_df["Disease"] == predicted_disease].iloc[:, 1:].values.flatten()
    
    return predicted_disease, description, precautions

if __name__ == "__main__":
    user_input = input("Enter symptoms (comma separated): ")
    user_symptoms = [sym.strip() for sym in user_input.split(",")]
    disease, desc, precautions = predict_disease(user_symptoms)
    
    print(f"\nPredicted Disease: {disease}")
    print(f"Description: {desc}")
    print("Precautions:")
    for i, p in enumerate(precautions, 1):
        print(f"{i}. {p}")
