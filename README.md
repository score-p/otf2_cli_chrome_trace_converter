# ChromeTrace2Otf2
This tool is developed to convert files from Chrome's Trace Event Format created by TensorFlow into OTF2 files.
Therefore, we only take care of features used by TensorFlow's traces at the moment.    


[Chrome Trace specification](https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU)

##TODO
* Timestamp sorting:  
  TensorFlow seems to write well sorted timestamps for each threads. Nevertheless, Google's trace specification does not require this.
* Dataflow
* Metric: Top allocations
