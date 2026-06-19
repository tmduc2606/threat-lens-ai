from pathlib import Path
import pandas as pd

def analyze_ips():
    # Load dataset
    data_dir = Path(__file__).resolve().parent.parent / "data"
    df = pd.read_csv(data_dir / "4_malicious_ips.csv")
    
    # Strip whitespace from column names and lowercase them
    df.columns = df.columns.str.strip()
    
    print(f"Total IP records in dataset: {len(df)}")
    
    # Filter for high severity
    high_severity_ips = df[df['Threat_Severity'].str.lower() == 'high']
    print(f"\nNumber of High Severity IPs: {len(high_severity_ips)}")
    
    # Display the High Severity IPs
    print("\n--- HIGH SEVERITY MALICIOUS IPs ---")
    cols_to_show = ['IP', 'Country', 'Owner', 'Malicious_Votes', 'Total_Reports', 'Reputation_Score', 'Threat_Label', 'Threat_Category']
    print(high_severity_ips[cols_to_show].to_string(index=False))
    
    # Sort by Malicious_Votes descending
    sorted_by_votes = df.sort_values(by='Malicious_Votes', ascending=False)
    print("\n--- TOP 15 IPs BY MALICIOUS VOTES (DESCENDING) ---")
    print(sorted_by_votes[cols_to_show].head(15).to_string(index=False))

if __name__ == "__main__":
    analyze_ips()
