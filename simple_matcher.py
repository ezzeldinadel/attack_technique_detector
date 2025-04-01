import json
import spacy
from nltk.metrics import edit_distance

# Load MITRE ATT&CK techniques and sub-techniques
# You can download the MITRE ATT&CK Enterprise matrix from https://attack.mitre.org/techniques/enterprise/
def load_attack_techniques(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

# Fuzzy matching function using edit distance
def fuzzy_match(alert_description, technique_name, threshold=2):
    distance = edit_distance(alert_description, technique_name)
    return distance <= threshold

# Initialize spaCy's NLP model
nlp = spacy.load("en_core_web_sm")

# Enhanced alert classification using fuzzy matching and NLP
def classify_alert(alert_description, attack_data):
    matched_techniques = []
    doc = nlp(alert_description.lower())
    
    for technique in attack_data:
        technique_name = technique.get("name", "").lower()
        sub_techniques = technique.get("sub-techniques", [])
        
        # Fuzzy match on technique name
        if fuzzy_match(doc.text, technique_name):
            matched_techniques.append({
                "technique_id": technique.get("id"),
                "name": technique_name,
                "type": "Technique"
            })
        
        # Fuzzy match on sub-techniques
        for sub_technique in sub_techniques:
            sub_technique_name = sub_technique.get("name", "").lower()
            if fuzzy_match(doc.text, sub_technique_name):
                matched_techniques.append({
                    "technique_id": sub_technique.get("id"),
                    "name": sub_technique_name,
                    "type": "Sub-Technique"
                })
    
    return matched_techniques

# Example usage
if __name__ == "__main__":
    # Load the MITRE ATT&CK data (replace 'attack_data.json' with the path to your data file)
    attack_data = load_attack_techniques('attack_data.json')
    
    # Define an example alert description
    alert_description = "Suspicious activity detected: brute force attack on user credentials."
    
    # Classify the alert
    classified_alerts = classify_alert(alert_description, attack_data)
    
    # Output results
    if classified_alerts:
        print(f"Alert Description: {alert_description}")
        print("Matched Techniques:")
        for match in classified_alerts:
            print(f"- {match['type']}: {match['name']} (ID: {match['technique_id']})")
    else:
        print("No techniques matched.")
