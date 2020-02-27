# About
This repository stores all the code used to produce results in "Improving Meek With Adversarial Techniques"

This project is under development. The specific commit used in "Improving Meek With Adversarial Techniques" was `64f13d433a40582c54ced2fc8a49bc7e4290feb3`

If you find this repository useful to your research, please cite our paper
```tex
  @inproceedings {239064,
  author = {Steven Sheffey and Ferrol Aderholdt},
  title = {Improving Meek With Adversarial Techniques},
  booktitle = {9th {USENIX} Workshop on Free and Open Communications on the Internet ({FOCI} 19)},
  year = {2019},
  address = {Santa Clara, CA},
  url = {https://www.usenix.org/conference/foci19/presentation/sheffey},
  publisher = {{USENIX} Association},
  month = aug,
}
```

# Data Collection
In the `data_collection` directory. This contains docker images and code to generate packet capture data for website navigation with and without Meek.

# Feature Extraction
In the `data_generator` directory. This contains code to extract useful features from the generated packet captures.

# Analysis
In the `analysis` directory. This contains code to train the machine learning models used in our research.
