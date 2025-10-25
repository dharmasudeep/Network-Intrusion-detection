#!/usr/bin/env python3
"""
Installation Verification Script
Checks all required packages and dependencies
"""

import sys

def check_python_version():
    """Check Python version"""
    print("🔍 Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"   ✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"   ❌ Python {version.major}.{version.minor}.{version.micro} (Need 3.8+)")
        return False

def check_package(package_name, import_name=None):
    """Check if a package is installed"""
    if import_name is None:
        import_name = package_name
    
    try:
        module = __import__(import_name)
        version = getattr(module, '__version__', 'unknown')
        print(f"   ✅ {package_name:20s} (version {version})")
        return True
    except ImportError:
        print(f"   ❌ {package_name:20s} NOT INSTALLED")
        return False

def main():
    print("=" * 70)
    print("🛡️  Network Attack Detection System - Installation Verification")
    print("=" * 70)
    
    all_ok = True
    
    # Check Python version
    if not check_python_version():
        all_ok = False
    
    print("\n📦 Checking Core Packages...")
    
    # Core packages
    packages = {
        'Flask': 'flask',
        'Werkzeug': 'werkzeug',
        'pandas': 'pandas',
        'numpy': 'numpy',
        'scikit-learn': 'sklearn'
    }
    
    for package, import_name in packages.items():
        if not check_package(package, import_name):
            all_ok = False
    
    print("\n📦 Checking Additional Dependencies...")
    
    # Additional dependencies
    additional = {
        'scipy': 'scipy',
        'joblib': 'joblib',
        'Jinja2': 'jinja2',
        'MarkupSafe': 'markupSafe',
        'click': 'click',
        'itsdangerous': 'itsdangerous'
    }
    
    for package, import_name in additional.items():
        check_package(package, import_name)  # Don't fail on these
    
    print("\n🔍 Checking Specific Imports...")
    
    # Test specific imports that the app uses
    specific_imports = [
        ('flask', 'Flask, render_template, request, jsonify, session'),
        ('pandas', 'DataFrame'),  # Changed from pd to DataFrame
        ('numpy', 'array'),      # Changed from np to array
        ('sklearn.model_selection', 'train_test_split'),
        ('sklearn.preprocessing', 'LabelEncoder, StandardScaler'),
        ('sklearn.ensemble', 'RandomForestClassifier'),
        ('sklearn.svm', 'SVC'),
        ('sklearn.neural_network', 'MLPClassifier'),
        ('sklearn.metrics', 'accuracy_score, classification_report, confusion_matrix'),
        ('pickle', 'dump, load'),  # Changed from pickle to dump, load
        ('os', 'path'),           # Changed from os to path
        ('werkzeug.utils', 'secure_filename')
    ]
    
    import_ok = True
    for module, items in specific_imports:
        try:
            exec(f"from {module} import {items}")
            print(f"   ✅ from {module} import {items}")
        except ImportError as e:
            print(f"   ❌ from {module} import {items}")
            print(f"      Error: {e}")
            import_ok = False
    
    if not import_ok:
        all_ok = False
    
    print("\n" + "=" * 70)
    
    if all_ok:
        print("✅ ALL CHECKS PASSED!")
        print("\n🚀 You're ready to run the application:")
        print("   python app.py")
        print("\n💡 Then open your browser to:")
        print("   http://localhost:5000")
    else:
        print("❌ SOME CHECKS FAILED!")
        print("\n🔧 To fix, run:")
        print("   pip install -r requirements.txt")
        print("\n   Or install individually:")
        print("   pip install Flask pandas numpy scikit-learn werkzeug")
    
    print("=" * 70)
    
    return all_ok

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)