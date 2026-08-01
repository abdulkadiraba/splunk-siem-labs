## Project Overview

This project documents my hands-on experience using Splunk Search Processing Language (SPL) to investigate security event data.

During this lab, I used SPL commands to investigate process activity, review event details, enrich log data, assign risk scores, and identify unusual authentication patterns.

## Lab Source 

- **Platform:** [TryHackMe](https://tryhackme.com)
- **Room Link:** [Splunk: Exploring SPL](https://tryhackme.com/room/splunkexploringspl).
 
---

## Skills Demonstrated

- Splunk Search Processing Language (SPL)
- Windows Event Log Analysis
- VPN Authentication Log Analysis
- Log Filtering and Transformation
- Process Investigation
- Regular Expressions (Regex)
- Data Enrichment
- Lookup Tables
- IP Geolocation
- Statistical Analysis
- Behavioral Anomaly Detection
- SIEM Investigation Fundamentals

---

## Tools Used

- Splunk Enterprise
- Search Processing Language (SPL)
- Windows Event Logs
- VPN Authentication Logs

---

# SPL Queries Practiced

## Searching Events Within a Specific Time Range

```spl
index=windowslogs earliest="04/15/2022:08:05:00" latest="04/15/2022:08:06:00"
| stats count
```

### Purpose:
I used this query to search Windows logs within a specific timeframe and count the number of events that occurred during that period.

### What I Learned:
Time-based searches allow me to focus on activity that occurred during a specific window of time, which is useful when investigating a security event or reviewing activity around an alert.

---

# Filtering Fields From Events

```spl
index=windowslogs
| fields Domain SourceProcessId TargetProcessId
```

### Purpose:
I used the `fields` command to display only the information needed for analysis. This allowed me to focus on domain information and process identifiers.

### What I Learned:
Filtering unnecessary fields helps reduce clutter in large datasets and allows me to focus on the information most relevant to an investigation.

---

# Creating Tables From Events

## Account Information Table

```spl
index=windowslogs
| table EventID AccountName AccountType
```

### Purpose:
I used the `table` command to organize specific event fields into a structured format.

### What I Learned:
Creating tables makes log data easier to read and helps highlight important details such as event IDs and account information.

---

## Process Timeline Investigation

```spl
index=windowslogs EventID=1
| table _time ParentProcessId ProcessId ParentCommandLine CommandLine
| reverse
```

### Purpose:
I used this query to examine Windows process creation events and display parent and child process information in chronological order.

### What I Learned:
Reviewing process relationships helps provide additional context when investigating how processes were created and executed.

---

# Finding Common Values Using the `top` Command

```spl
index=windowslogs
| top Image
```

### Purpose:
I used the `top` command to identify the most frequently occurring values within the `Image` field.

### What I Learned:
The `top` command helps summarize large amounts of data by showing the values that appear most often. This can help establish what activity is common within the dataset.

---

# Removing Duplicate Values Using `dedup`

```spl
index=windowslogs
| dedup Image
```

### Purpose:
I used the `dedup` command to remove duplicate values from the search results.

### What I Learned:
Removing duplicate results helps make data easier to review by reducing repeated information.

---

# Renaming Fields

```spl
index=windowslogs
| fields EventID User Image Hostname SourceIp
| rename User as Employee
```

### Purpose:
I used the `fields` command to select the information I wanted to review and then used `rename` to change the `User` field to `Employee` for easier interpretation.

### What I Learned:
Renaming fields improves readability when analyzing log data and documenting investigation results.

---

# Filtering Data Using Regular Expressions

## Filtering Executable Files

```spl
index=windowslogs
| regex Image="\.exe$"
```

### Purpose:
I used the regex command to filter windows logs event where the `Image` field ends with `.exe`. The expression `\.exe$` matches values that end with the executable file extension. 

### What I Learned:
Regular expressions allow me to search for specific patterns within log data. In this case, I used regex to narrow down events involving executable files. 

---

## Filtering Registry Activity

```spl
index=windowslogs
| regex TargetObject="Manager$"
```

### Purpose:
I used regex to filter events where the `TargetObject` field matched a specific pattern.

### What I Learned:
Regex provides flexibility when searching through large datasets where exact matches may not be enough.

---

# Enriching IP Addresses With Geographic Information

```spl
index=windowslogs
| iplocation SourceIp
| stats count by Region
```

### Purpose:
I used the `iplocation` command to add geographic information to IP addresses and summarize events by region.

### What I Learned:
Adding geographic context to IP addresses provides additional information when reviewing network activity.

---

# Assigning Risk Scores Using Lookup Tables

```spl
index=windowslogs
| lookup image_risk score Image OUTPUT Riskscore
| search Riskscore=3
| stats count by Image Riskscore
| sort -Riskscore
```

### Purpose:
I used a lookup table to match executable names with risk scores and identify events associated with higher-risk images.

### What I Learned:
Lookup tables allow additional context to be added to raw event data, making it easier to prioritize information during an investigation.

---

# Detecting VPN Country Anomalies

```spl
index=vpnlogs
| eventstats count as logins_by_user by user
| eventstats count as logins_by_user_country by src_country
| eval country_freq=logins_by_user_country/logins_by_user
| where country_freq < 0.1
| table _time user src_ip src_country country_freq
```

### Purpose:
I used this query to compare user login activity across different countries and identify locations that were uncommon for a user's normal behavior.

### What I Learned:
Analyzing login locations can help identify unusual authentication activity that may require further investigation.

---

# Detecting VPN Login Time Anomalies

```spl
index=vpnlogs
| eval hour=tonumber(strftime(_time,"%H")) + tonumber(strftime(_time,"%M"))/60
| eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
| eval zscore=abs(hour - typical_hour) / stdev_hour
| where zscore > 3
| eval hour=round(hour,2), typical_hour=round(typical_hour,2)
| eval stdev_hour=round(stdev_hour,2), zscore=round(zscore,2)
| table _time user src_ip src_country hour typical_hour stdev_hour zscore
| sort - hour_zscore
```

### Purpose:
I used statistical analysis to compare VPN login times against typical user behavior and identify login events that significantly deviated from the normal pattern.

### What I Learned:
Behavioral analysis can help identify unusual authentication activity that may indicate suspicious account behavior.

---

# Key Takeaways

Through this lab, I gained practical experience using Splunk for security log analysis. I practiced searching Windows and VPN logs, filtering information, investigating processes, enriching data, and identifying abnormal activity patterns.

This project strengthened my understanding of how SIEM tools can be used to analyze security events and investigate potential threats.
