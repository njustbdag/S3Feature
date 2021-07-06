# S3Feature

## Abstract
A Static Sensitive Subgraph-based Feature for Android Malware Detection, we propose a novel static sensitive subgraph-based feature for Android malware detection, named S3Featrue. 

## Steps
First, to represent Android applications with high level characteristics, we develop a sensitive function call graph (SFCG) by extending a function call graph (FCG) through tagging sensitive nodes on it. A malicious score is evaluated to identify sensitive nodes. 
Second, a large amount of sensitive sub-graphs (SSGs) and their neighbor sub-graphs (NSGs) are mined from a SFCG to characterize suspicious behaviors of applications. 
Finally, after removing repetitive or isomorphic sub-graphs, the remaining SSGs and NSGs are encoded into a feature vector to represent each application. 

## Results
For malware detection, S3Featrue achieves 97.04% F1-score, which performs better than other well-studies features. And a combination of S3Featrue and other features achieves 97.71% F1-score, which shows that S3Feature is a good potential feature in improving the performance of malware detection approaches or tools.
