import os
import pandas as pd

directory = "./"

def clean_dtype(dtype):
    dtype = str(dtype)
    if "int" in dtype:
        return "int"
    elif "float" in dtype:
        return "float"
    elif "bool" in dtype:
        return "bool"
    else:
        return "string"

result = []

for file in os.listdir(directory):
    if file.endswith(".csv"):
        file_path = os.path.join(directory, file)

        try:
            df = pd.read_csv(file_path)
            column_types = {col: clean_dtype(dtype) for col, dtype in df.dtypes.items()}
            result.append({file: column_types})

        except Exception as e:
            print(f"Error reading {file}: {e}")

print(result)
