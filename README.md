# CS4331-Project3

### Network Example: 
https://jvermill91.github.io/CS4331-P3/networkExample.html

### Data
Our data shows the network taffric for Kyoto University's [Honeypots](https://en.wikipedia.org/wiki/Honeypot_(computing)).

The raw data is scource is from here: http://www.takakura.com/Kyoto_data/new_data201704/

A description of the data can be found here: http://www.takakura.com/Kyoto_data/BenchmarkData-Description-v5.pdf

Some of the infomation available in the data is listen below:

* Data Fields
  * Connection Date
  * Connection Time
  * Host IP
  * Source IP
  * Service type
  * IDS detection
  * Malware detection
  * Shellcode detection
  
For our visualization, we would like to show the connections in the data using networks.  The main relationships we want to show are different types of attacks (malware, shell code, etc.) that are launched on the different types of services (SMTP, DNS, HTTP, etc.) hosted by the various nodes on the cluster. Another possible interesting relationship we could visualize include the types of attacks and types of services attacked with the attacks originating from the same source IP addresses. In addition, we could add another dimension to the visualization by adding a time selector allowing the user to visualize the changes in the frequency and type of attacks over a given time period.

* Visualizations:
  * Graph showing attacks grouped by the service they target on different host
  * Graph visualizing attacks originating from the same source IP addresses
  * A time compenent for both graphs allowing the user to visualize how the type and source of attacks has changed over time
