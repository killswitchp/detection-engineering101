import os

for root,dirs, files in os.walk(r"C:\Users\paava\Documents\DE-Python"):
    for file in files:
        if file.endswith(".toml"):
          print(file)