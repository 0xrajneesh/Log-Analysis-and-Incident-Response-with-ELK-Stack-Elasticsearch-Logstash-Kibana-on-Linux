# Log Analysis and Incident Response with ELK Stack (Elasticsearch, Logstash, Kibana) on Linux

## Introduction

Log analysis is a critical component of incident response, enabling security professionals to identify, investigate, and mitigate security incidents. The ELK Stack (Elasticsearch, Logstash, Kibana) is a powerful suite of tools for aggregating, searching, visualizing, and analyzing log data. This advanced-level lab will guide you through setting up the ELK Stack to analyze Linux logs for security incidents, creating visualizations and alerts, and responding to potential threats.

## Pre-requisites

- Advanced knowledge of Linux operating systems and command-line interface
- Understanding of log formats and log management
- Familiarity with network and system security concepts
- Basic knowledge of scripting and regular expressions

## Lab Set-up and Tools

- A computer running a Linux distribution (e.g., Ubuntu)
- [Elasticsearch](https://www.elastic.co/downloads/elasticsearch) installed
- [Logstash](https://www.elastic.co/downloads/logstash) installed
- [Kibana](https://www.elastic.co/downloads/kibana) installed
- Linux log files (e.g., syslog, auth.log)

### Installing Elasticsearch

1. Download and install the public signing key:
    ```bash
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    ```
2. Install the APT repository:
    ```bash
    sudo sh -c 'echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list'
    ```
3. Install Elasticsearch:
    ```bash
    sudo apt update
    sudo apt install elasticsearch
    ```
4. Start and enable Elasticsearch:
    ```bash
    sudo systemctl start elasticsearch
    sudo systemctl enable elasticsearch
    ```

### Installing Logstash

1. Install Logstash:
    ```bash
    sudo apt install logstash
    ```
2. Start and enable Logstash:
    ```bash
    sudo systemctl start logstash
    sudo systemctl enable logstash
    ```

### Installing Kibana

1. Install Kibana:
    ```bash
    sudo apt install kibana
    ```
2. Start and enable Kibana:
    ```bash
    sudo systemctl start kibana
    sudo systemctl enable kibana
    ```

## Exercises

### Exercise 1: Setting Up Logstash for Log Ingestion

**Objective**: Configure Logstash to ingest Linux logs, parse them, and store them in Elasticsearch for further analysis.

1. Create a Logstash configuration file:
    ```bash
    sudo nano /etc/logstash/conf.d/logstash.conf
    ```
2. Add input, filter, and output plugins for log ingestion:
    ```plaintext
    input {
      file {
        path => "/var/log/syslog"
        start_position => "beginning"
      }
    }

    filter {
      grok {
        match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:message}" }
      }
      date {
        match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      }
    }

    output {
      elasticsearch {
        hosts => ["localhost:9200"]
        index => "syslog-%{+YYYY.MM.dd}"
      }
    }
    ```
3. Restart Logstash to apply the configuration:
    ```bash
    sudo systemctl restart logstash
    ```

**Expected Output**: Logstash ingesting syslog data into Elasticsearch.

### Exercise 2: Creating Index Patterns and Visualizations in Kibana

**Objective**: Set up Kibana index patterns and create visualizations to make the log data easily accessible and understandable.

1. Access Kibana by opening a web browser and navigating to `http://localhost:5601`.
2. Create an index pattern for the ingested logs:
    - Go to "Management" > "Index Patterns" > "Create Index Pattern".
    - Enter `syslog-*` as the index pattern and select `timestamp` as the time field.
3. Create visualizations:
    - Go to "Visualize" > "Create new visualization".
    - Select a visualization type (e.g., line chart, bar chart) and configure it to display log data.

**Expected Output**: Visualizations displaying log data in Kibana.

### Exercise 3: Analyzing Log Data for Security Incidents

**Objective**: Use Kibana to analyze log data and identify potential security incidents based on patterns and anomalies.

1. Go to "Discover" in Kibana.
2. Use Kibana's search and filter functionalities to analyze log data for anomalies and suspicious activities.
    - Example query: `program: "sshd" AND message: "Failed password"`
3. Document any identified security incidents, including the nature of the incident and the affected systems.

**Expected Output**: Identification and documentation of potential security incidents.

### Exercise 4: Setting Up Alerts for Critical Log Events

**Objective**: Configure Kibana to generate alerts for critical log events to ensure timely detection and response.

1. Go to "Management" > "Watcher" > "Create Advanced Watch".
2. Define a watch that triggers an alert based on a specified condition:
    - Set the trigger schedule (e.g., every 5 minutes).
    - Define the input (e.g., search for "sshd" failed login attempts).
    - Set the condition (e.g., alert if the number of failed login attempts exceeds a threshold).
    - Configure the action (e.g., send an email notification).
3. Save and activate the watch.

**Expected Output**: Alerts configured and tested in Kibana, with notifications sent for critical log events.

### Exercise 5: Incident Response and Mitigation

**Objective**: Develop an incident response plan based on log analysis and implement mitigation actions for identified incidents.

1. Create an incident response plan based on the identified security incidents.
2. Implement response actions (e.g., blocking IP addresses, updating firewall rules, isolating affected systems).
3. Document the response actions and their outcomes.
4. Review and refine the incident response plan based on the lessons learned.

**Expected Output**: An incident response plan, implemented response actions, and documentation of outcomes and improvements.

### Advanced Exercises

### Exercise 6: Parsing Complex Log Formats

**Objective**: Use Logstash to parse and analyze complex log formats, such as Apache access logs, for deeper insights.

1. Obtain a sample Apache access log file.
2. Create a new Logstash configuration file to parse the Apache log format:
    ```bash
    sudo nano /etc/logstash/conf.d/apache_log.conf
    ```
    Add the following configuration:
    ```plaintext
    input {
      file {
        path => "/path/to/apache/access.log"
        start_position => "beginning"
      }
    }

    filter {
      grok {
        match => { "message" => "%{COMBINEDAPACHELOG}" }
      }
    }

    output {
      elasticsearch {
        hosts => ["localhost:9200"]
        index => "apache-logs-%{+YYYY.MM.dd}"
      }
    }
    ```
3. Restart Logstash to apply the new configuration:
    ```bash
    sudo systemctl restart logstash
    ```

**Expected Output**: Parsed Apache access logs indexed in Elasticsearch.

### Exercise 7: Correlating Multiple Log Sources

**Objective**: Correlate events from multiple log sources to detect advanced threats and gain comprehensive insights.

1. Obtain sample logs from multiple sources (e.g., syslog, auth.log, web server logs).
2. Configure Logstash to ingest and parse these logs:
    ```bash
    sudo nano /etc/logstash/conf.d/multi_source.conf
    ```
    Add input, filter, and output plugins for each log source.
3. Use Kibana to create visualizations that correlate events across the different log sources.
    - Example: Correlate failed SSH login attempts with web server activity.

**Expected Output**: Correlated visualizations showing patterns across multiple log sources.

### Exercise 8: Creating Advanced Alerts with Machine Learning

**Objective**: Use machine learning in Kibana to create advanced alerts for anomalous behavior detected in log data.

1. Go to the "Machine Learning" section in Kibana.
2. Create a new job to analyze a specific log type for anomalies.
    - Select the index pattern and set the analysis parameters.
3. Define an alert that triggers when an anomaly is detected.
    - Set the conditions and actions for the alert.

**Expected Output**: Advanced alerts based on machine learning analysis, detecting anomalies in log data.

### Exercise 9: Logstash Pipeline Optimization

**Objective**: Optimize Logstash pipelines for performance and scalability by improving configuration efficiency.

1. Review the existing Logstash configuration files for inefficiencies.
2. Implement improvements such as:
    - Using conditionals to filter out irrelevant logs early in the pipeline.
    - Reducing the number of Grok patterns.
    - Using the `geoip` filter for IP address enrichment.
3. Benchmark the performance before and after optimization.

**Expected Output**: Optimized Logstash pipelines with improved performance and scalability.

### Exercise 10: Data Enrichment and Geolocation

**Objective**: Enrich log data with additional context and geolocation information for enhanced analysis.

1. Obtain a sample log file containing IP addresses.
2. Create a Logstash configuration file to enrich the log data with geolocation information:
    ```bash
    sudo nano /etc/logstash/conf.d/geolocation.conf
    ```
    Add the following configuration:
    ```plaintext
    input {
      file {
        path => "/path/to/logfile.log"
        start_position => "beginning"
      }
    }

    filter {
      grok {
        match => { "message" => "%{IPORHOST:client_ip} %{GREEDYDATA:message}" }
      }
      geoip {
        source => "client_ip"
      }
    }

    output {
      elasticsearch {
        hosts => ["localhost:9200"]
        index => "geo-logs-%{+YYYY.MM.dd}"
      }
    }
    ```
3. Restart Logstash to apply the new configuration:
    ```bash
    sudo systemctl restart logstash
    ```

**Expected Output**: Enriched log data with geolocation information indexed in Elasticsearch.

## Conclusion

By completing these exercises, you have gained advanced skills in log analysis and incident response using the ELK Stack on a Linux system. You have learned how to set up Logstash for log ingestion, create visualizations in Kibana, analyze log data for security incidents, configure alerts for critical events, and develop and implement an incident response plan. These skills are essential for effective log management and incident response in a cybersecurity context.
