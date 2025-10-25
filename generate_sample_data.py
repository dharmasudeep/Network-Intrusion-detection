import pandas as pd
import numpy as np
import random

def generate_sample_network_data(num_samples=1000, output_file='sample_network_data.csv'):
    """
    Generate sample network traffic data similar to NSL-KDD dataset
    with attack types commonly used in intrusion detection systems
    """
    
    np.random.seed(42)
    random.seed(42)
    
    # Define possible values for categorical features
    protocol_types = ['tcp', 'udp', 'icmp']
    services = ['http', 'smtp', 'ftp', 'ssh', 'domain', 'ftp_data', 'private', 
                'telnet', 'finger', 'pop_3', 'imap4', 'IRC', 'eco_i', 'other']
    flags = ['SF', 'S0', 'REJ', 'RSTR', 'RSTO', 'SH', 'S1', 'S2', 'RSTOS0', 'S3', 'OTH']
    
    # Attack types - comprehensive list matching NSL-KDD
    # Categories: normal, DoS, Probe, R2L, U2R
    attack_types = {
        'normal': 'normal',
        # DoS attacks
        'neptune': 'DoS',
        'smurf': 'DoS', 
        'back': 'DoS',
        'teardrop': 'DoS',
        'pod': 'DoS',
        'land': 'DoS',
        # Probe attacks
        'portsweep': 'Probe',
        'ipsweep': 'Probe',
        'nmap': 'Probe',
        'satan': 'Probe',
        'saint': 'Probe',
        'mscan': 'Probe',
        # R2L attacks (Remote to Local)
        'warezclient': 'R2L',
        'guess_passwd': 'R2L',
        'warezmaster': 'R2L',
        'ftp_write': 'R2L',
        'imap': 'R2L',
        'phf': 'R2L',
        'multihop': 'R2L',
        'spy': 'R2L',
        # U2R attacks (User to Root)
        'buffer_overflow': 'U2R',
        'rootkit': 'U2R',
        'loadmodule': 'U2R',
        'perl': 'U2R'
    }
    
    data = []
    
    # Distribution: 60% normal, 20% DoS, 10% Probe, 7% R2L, 3% U2R
    attack_distribution = {
        'normal': 0.60,
        'DoS': 0.20,
        'Probe': 0.10,
        'R2L': 0.07,
        'U2R': 0.03
    }
    
    for i in range(num_samples):
        # Randomly select attack category based on distribution
        rand_val = random.random()
        cumulative = 0
        selected_category = 'normal'
        
        for category, prob in attack_distribution.items():
            cumulative += prob
            if rand_val <= cumulative:
                selected_category = category
                break
        
        # Select specific attack from category
        if selected_category == 'normal':
            label = 'normal'
            is_attack = False
        else:
            # Get all attacks in this category
            attacks_in_category = [k for k, v in attack_types.items() if v == selected_category]
            label = random.choice(attacks_in_category)
            is_attack = True
        
        # Generate features based on attack type
        if label == 'normal':
            # Normal traffic characteristics
            duration = random.randint(0, 300)
            protocol = random.choice(['tcp', 'udp', 'icmp'])
            service = random.choice(['http', 'smtp', 'ftp', 'ssh', 'domain', 'private'])
            flag = random.choice(['SF', 'S0', 'REJ'])
            src_bytes = random.randint(50, 10000)
            dst_bytes = random.randint(50, 10000)
            land = 0
            wrong_fragment = 0
            urgent = 0
            count = random.randint(1, 50)
            srv_count = random.randint(1, 50)
            serror_rate = random.uniform(0.0, 0.1)
            rerror_rate = random.uniform(0.0, 0.1)
            same_srv_rate = random.uniform(0.7, 1.0)
            diff_srv_rate = random.uniform(0.0, 0.3)
            num_failed_logins = 0
            logged_in = 1
            num_compromised = 0
            root_shell = 0
            su_attempted = 0
            num_root = 0
            num_file_creations = random.randint(0, 5)
            num_shells = 0
            num_access_files = random.randint(0, 5)
            
        elif label in ['neptune', 'smurf', 'back', 'teardrop', 'pod', 'land']:
            # DoS attacks - high connection rates, low duration
            duration = random.randint(0, 5)
            protocol = 'tcp' if label in ['neptune', 'back'] else random.choice(['tcp', 'udp', 'icmp'])
            service = random.choice(['http', 'private', 'eco_i', 'other'])
            flag = random.choice(['S0', 'REJ', 'RSTO', 'RSTOS0'])
            src_bytes = random.randint(0, 100)
            dst_bytes = random.randint(0, 100)
            land = 1 if label == 'land' else 0
            wrong_fragment = random.randint(0, 3)
            urgent = 0
            count = random.randint(100, 511)
            srv_count = random.randint(100, 511)
            serror_rate = random.uniform(0.8, 1.0)
            rerror_rate = random.uniform(0.0, 0.2)
            same_srv_rate = random.uniform(0.8, 1.0)
            diff_srv_rate = random.uniform(0.0, 0.1)
            num_failed_logins = 0
            logged_in = 0
            num_compromised = 0
            root_shell = 0
            su_attempted = 0
            num_root = 0
            num_file_creations = 0
            num_shells = 0
            num_access_files = 0
            
        elif label in ['portsweep', 'ipsweep', 'nmap', 'satan', 'saint', 'mscan']:
            # Probe attacks - scanning patterns
            duration = random.randint(0, 10)
            protocol = random.choice(['tcp', 'udp', 'icmp'])
            service = random.choice(['private', 'eco_i', 'other'])
            flag = random.choice(['SF', 'S0', 'REJ', 'RSTO'])
            src_bytes = random.randint(0, 50)
            dst_bytes = random.randint(0, 50)
            land = 0
            wrong_fragment = 0
            urgent = 0
            count = random.randint(50, 300)
            srv_count = random.randint(1, 10)
            serror_rate = random.uniform(0.5, 1.0)
            rerror_rate = random.uniform(0.0, 0.5)
            same_srv_rate = random.uniform(0.0, 0.3)
            diff_srv_rate = random.uniform(0.5, 1.0)
            num_failed_logins = 0
            logged_in = 0
            num_compromised = 0
            root_shell = 0
            su_attempted = 0
            num_root = 0
            num_file_creations = 0
            num_shells = 0
            num_access_files = 0
            
        elif label in ['warezclient', 'guess_passwd', 'warezmaster', 'ftp_write', 'imap', 'phf', 'multihop', 'spy']:
            # R2L attacks - unauthorized access attempts
            duration = random.randint(0, 100)
            protocol = 'tcp'
            service = random.choice(['ftp', 'telnet', 'ftp_data', 'http', 'smtp'])
            flag = random.choice(['SF', 'S0', 'REJ'])
            src_bytes = random.randint(100, 10000)
            dst_bytes = random.randint(0, 1000)
            land = 0
            wrong_fragment = 0
            urgent = 0
            count = random.randint(1, 20)
            srv_count = random.randint(1, 10)
            serror_rate = random.uniform(0.0, 0.3)
            rerror_rate = random.uniform(0.0, 0.3)
            same_srv_rate = random.uniform(0.3, 0.7)
            diff_srv_rate = random.uniform(0.2, 0.5)
            num_failed_logins = random.randint(0, 5) if label == 'guess_passwd' else 0
            logged_in = random.randint(0, 1)
            num_compromised = random.randint(0, 5)
            root_shell = 0
            su_attempted = 0
            num_root = 0
            num_file_creations = random.randint(0, 10)
            num_shells = 0
            num_access_files = random.randint(0, 10)
            
        else:  # U2R attacks
            # U2R attacks - privilege escalation
            duration = random.randint(0, 200)
            protocol = 'tcp'
            service = random.choice(['telnet', 'ftp', 'ssh', 'http'])
            flag = 'SF'
            src_bytes = random.randint(100, 5000)
            dst_bytes = random.randint(100, 5000)
            land = 0
            wrong_fragment = 0
            urgent = 0
            count = random.randint(1, 10)
            srv_count = random.randint(1, 10)
            serror_rate = random.uniform(0.0, 0.2)
            rerror_rate = random.uniform(0.0, 0.2)
            same_srv_rate = random.uniform(0.5, 1.0)
            diff_srv_rate = random.uniform(0.0, 0.3)
            num_failed_logins = random.randint(0, 3)
            logged_in = 1
            num_compromised = random.randint(1, 10)
            root_shell = random.randint(0, 1)
            su_attempted = random.randint(0, 2)
            num_root = random.randint(1, 100)
            num_file_creations = random.randint(1, 20)
            num_shells = random.randint(0, 5)
            num_access_files = random.randint(1, 20)
        
        # Create record with all 41 features (NSL-KDD standard)
        record = {
            'duration': duration,
            'protocol_type': protocol,
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': land,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'hot': random.randint(0, 30),
            'num_failed_logins': num_failed_logins,
            'logged_in': logged_in,
            'num_compromised': num_compromised,
            'root_shell': root_shell,
            'su_attempted': su_attempted,
            'num_root': num_root,
            'num_file_creations': num_file_creations,
            'num_shells': num_shells,
            'num_access_files': num_access_files,
            'num_outbound_cmds': 0,
            'is_host_login': random.randint(0, 1),
            'is_guest_login': random.randint(0, 1) if not logged_in else 0,
            'count': count,
            'srv_count': srv_count,
            'serror_rate': round(serror_rate, 2),
            'srv_serror_rate': round(serror_rate * random.uniform(0.8, 1.2), 2),
            'rerror_rate': round(rerror_rate, 2),
            'srv_rerror_rate': round(rerror_rate * random.uniform(0.8, 1.2), 2),
            'same_srv_rate': round(same_srv_rate, 2),
            'diff_srv_rate': round(diff_srv_rate, 2),
            'srv_diff_host_rate': round(random.uniform(0.0, 1.0), 2),
            'dst_host_count': random.randint(0, 255),
            'dst_host_srv_count': random.randint(0, 255),
            'dst_host_same_srv_rate': round(random.uniform(0.0, 1.0), 2),
            'dst_host_diff_srv_rate': round(random.uniform(0.0, 1.0), 2),
            'dst_host_same_src_port_rate': round(random.uniform(0.0, 1.0), 2),
            'dst_host_srv_diff_host_rate': round(random.uniform(0.0, 1.0), 2),
            'dst_host_serror_rate': round(serror_rate * random.uniform(0.7, 1.3), 2),
            'dst_host_srv_serror_rate': round(serror_rate * random.uniform(0.7, 1.3), 2),
            'dst_host_rerror_rate': round(rerror_rate * random.uniform(0.7, 1.3), 2),
            'dst_host_srv_rerror_rate': round(rerror_rate * random.uniform(0.7, 1.3), 2),
            'label': label
        }
        
        data.append(record)
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    
    print(f"✅ Sample dataset generated successfully!")
    print(f"📊 Total records: {len(df)}")
    print(f"📁 File saved: {output_file}")
    print(f"\n📈 Attack Distribution:")
    attack_counts = df['label'].value_counts()
    for attack, count in attack_counts.items():
        percentage = (count / len(df)) * 100
        print(f"   {attack:20s}: {count:5d} ({percentage:5.2f}%)")
    
    print(f"\n📊 Attack Category Distribution:")
    # Map labels to categories
    df['category'] = df['label'].map(attack_types)
    category_counts = df['category'].value_counts()
    for category, count in category_counts.items():
        percentage = (count / len(df)) * 100
        print(f"   {category:10s}: {count:5d} ({percentage:5.2f}%)")
    
    print(f"\n💾 File size: {df.memory_usage(deep=True).sum() / 1024:.2f} KB")
    print(f"📋 Features: {len(df.columns) - 1} (+ 1 label)")
    
    return df

if __name__ == "__main__":
    # Generate sample data
    print("🚀 Generating sample network traffic data...")
    print("=" * 70)
    
    # Generate different sizes for testing
    print("\n[1] Generating 5K dataset (recommended for demo)...")
    generate_sample_network_data(num_samples=5000, output_file='sample_network_data_5k.csv')
    
    print("\n" + "=" * 70)
    print("\n[2] Generating 1K dataset (for quick testing)...")
    generate_sample_network_data(num_samples=1000, output_file='sample_network_data_1k.csv')
    
    print("\n" + "=" * 70)
    print("✨ Generation complete!")
    print("\n📝 Usage:")
    print("1. Run this script: python generate_sample_data.py")
    print("2. Upload the generated CSV file in the web application")
    print("3. Use sample_network_data_5k.csv for best results")
    print("4. Use sample_network_data_1k.csv for quick testing")
    print("\n💡 Files created:")
    print("   - sample_network_data_5k.csv (5,000 records)")
    print("   - sample_network_data_1k.csv (1,000 records)")