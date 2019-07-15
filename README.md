# About
This repository stores all the code used to produce results in "<title>"

If this research is useful to your research, please cite our paper
```tex
@InProceedings{sheffey2019improving,
  author = {Sheffey, Steven and Aderholdt, Ferrol},
  title = {Improving Meek With Adversarial Techniques},
  booktitle = {9th USENIX Workshop on Free and Open Communications on the Internet},
  month = {August},
  year = {2019}
}
```

# Data Collection
In the `data_collection` directory. This contains docker images and code to generate packet capture data for website navigation with and without tor, and with pluggable transports.

# Feature Extraction
In the `data_generator` directory. This contains code to extract useful features from the generated packet captures.

# Analysis
In the `analysis` directory. This contains code to train the machine learning models used in our research.
