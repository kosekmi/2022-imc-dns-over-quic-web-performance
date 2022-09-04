# DNS Privacy with Speed? Evaluating DNS over QUIC and its Impact on Web Performance

Mike Kosek<sup>1</sup> | Luca Schumann<sup>1</sup> | Robin Marx<sup>2</sup> | Trinh Viet Doan<sup>1</sup> | Vaibhav Bajpai<sup>3</sup>

<sup>1</sup> Technical University of Munich | <sup>2</sup> KU Leuven | <sup>3</sup> CISPA Helmholtz Center for Information Security

[IMC 2022](https://conferences.sigcomm.org/imc/2022/), October 25&ndash;27, 2022.

[Paper &rarr;] tba

---

## Tools

The following tools were enhanced for our paper;

1. DNSPerf: Performance measurement library for DoQ, DoUDP, DoTCP, DoT, and DoH 
* Repository: https://github.com/mgranderath/dnsperf
* Pull Request adding support for QUIC Address Validation as well as TLS 1.3 Session Resumption and 0-RTT for DoQ, DoT, and DoH: tba

2. DNS Measurements: Performance measurement tool for DoQ, DoUDP, DoTCP, DoT, and DoH
* Repository: https://github.com/mgranderath/dns-measurements
* Pull Request adding support for QUIC Address Validation as well as TLS 1.3 Session Resumption and 0-RTT for DoQ, DoT, and DoH: tba

3. DNS Proxy: Simple DNS Proxy Server supporting DoQ, DoUDP, DoTCP, DoT, and DoH. 
* Repository: https://github.com/AdguardTeam/dnsproxy
* Fork used in the paper: https://github.com/justus237/dnsproxy
* Pull request adding support for QUIC Address Validation as well as TLS 1.3 Session Resumption and 0-RTT for DoQ, DoT, and DoH: tba
* Pull request DoT connection re-use: tba 

---

## Reproducibility

In order to enable the reproduction of our findings, we make the developed tools, the raw data of our measurements, and the analysis scripts publicly available. Please note, that our analysis scripts use ip-api (https://ip-api.com) for IP-to-Geolocation mapping. Due to changes in IP ownership, the data derived from the API might change over time. For our paper, we queried the APIs on the 16.05.2022.

0. Repository Overview
* The files ```single.query.response.times.ipynb``` and ```web.performance.ipynb``` are the analysis scripts for the ```single query response time``` and ```web performance``` measurements
* The folders ```single.query.response.times.zip``` and ```web.performance.zip``` contain the dataset as well as supplementary files for the ```single query response time``` and ```web performance``` measurements

1. Preparations
* Clone this repository to a machine running ```Jupyter Notebook``` or ```JupyterLab```
* Extract ```single.query.response.times.zip``` to the subdirectory ```single.query.response.times/```
* Extract ```web.performance.zip``` to the subdirectory ```web.performance/```

3. Single Query Response Times
* Run the Jupyter Notebook ```single.query.response.times.ipynb```

4. Web Performance
* Run the Jupyter Notebook ```web.performance.ipynb```

---

## Contact

Please feel welcome to contact the authors for further details.

* Mike Kosek (kosek@in.tum.de) (corresponding author)
* Luca Schumann
* Robin Marx (robin.marx@uhasselt.be)
* Trinh Viet Doan (doan@in.tum.de)
* Vaibhav Bajpai (bajpai@cispa.de)
