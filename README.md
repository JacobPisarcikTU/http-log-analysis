# HTTP Log Analysis in Splunk

## Objective

Use Splunk to ingest and analyze HTTP logs, detect suspicious web activity, identify server errors, and review large file transfers in web traffic.

### Skills Learned

- SIEM log ingestion and log analysis
- Basic Splunk searching and reporting
- Reviewing HTTP traffic and server errors
- Identifying suspicious user agents and unusual web activity
- Working with JSON-formatted Zeek-style HTTP logs

### Tools Used

- Splunk
- HTTP logs
- JSON log data
- Zeek-style HTTP logs

## Steps

### 1. Upload the HTTP Logs into Splunk

![Screenshot 1](screenshots/1.png)

I started this project by uploading the `http_logs.json` file into Splunk. To do this, I opened Splunk, went to Settings, selected Add Data, and chose the HTTP log file for upload. This was the first step in getting the dataset into the SIEM so I could begin working with it in a searchable format.

### 2. Set the Source Type and Index

![Screenshot 2](screenshots/2.png)
![Screenshot 3](screenshots/3.png)

After selecting the file, I followed the upload prompts and reviewed the settings Splunk would use for ingestion. The source type was set to `_json`, which matched the format of the log file. Since I had already completed the SSH log project, I decided to create a separate index called `http_lab` so the HTTP data would stay organized and be easier to search later. Keeping the projects separated made the workflow cleaner and reduced the chance of mixing data sources when writing queries.

### 3. Search the Logs

![Screenshot 4](screenshots/4.png)

To verify that the data was indexed correctly, I ran the following search:

    index=http_lab sourcetype="_json"

This search checks the `http_lab` index for events using the `_json` sourcetype. It is a simple first check, but it matters because it confirms that the log file was uploaded successfully and that the events are searchable before moving on to deeper analysis.

What I found:  
The search returned the uploaded HTTP events and showed that the dataset had been indexed correctly. Splunk also extracted useful fields such as `event_type`, `id.orig_h`, `id.resp_h`, `method`, `status_code`, `uri`, `user_agent`, and `resp_body_len`. This mattered because it confirmed the data was not only present, but also structured well enough to support the rest of the investigation.

### 4. Find the Top Endpoints Generating Web Traffic

![Screenshot 5](screenshots/5.png)

To identify the endpoints generating the most web traffic, I used the following query:

    index=http_lab sourcetype="_json"
    | stats count by "id.orig_h"
    | sort -count
    | head 10

This query groups the HTTP events by source IP address, counts how many events came from each endpoint, sorts the counts from highest to lowest, and returns the top 10. I wanted to start here because it gives a quick baseline of which systems in the dataset were the most active before narrowing in on more suspicious behavior.

What I found:  
The results showed that `10.0.0.28` generated the most HTTP traffic with `76` events, followed closely by `10.0.0.31` and `10.0.0.42` with `73` each, and `10.0.0.27` with `72`. This mattered because identifying the busiest systems gives useful context for the rest of the analysis. If one of these same endpoints also appears in suspicious user-agent activity, repeated errors, or large transfers, it becomes more meaningful from an investigation standpoint.

### 5. Count Server Errors

![Screenshot 6](screenshots/6.png)

To count the number of HTTP server errors in the 5xx range, I used the following query:

    index=http_lab sourcetype="_json" status_code>=500 status_code<600
    | stats count as server_errors

![Screenshot 7](screenshots/7.png)
![Screenshot 8](screenshots/8.png)

After getting the total count, I clicked the result and selected View Events so I could inspect the raw events behind it instead of stopping at the summary.

This query filters the dataset to HTTP events with status codes from `500` through `599`, then counts the number of matching events. That makes it a quick way to measure how much server-side error activity is present in the dataset before drilling down into the details.

What I found:  
The search returned `285` server error events, and drilling into the result showed individual events with status codes such as `500` and `503`. This mattered because a large number of 5xx responses can point to server instability, application issues, or activity that is triggering failures on the server side. Looking at the raw events helped confirm that the count reflected real error activity in the dataset.

### 6. Identify Suspicious User Agents

![Screenshot 9](screenshots/9.png)

To identify user agents associated with possible scripted or automated activity, I ran the following query:

    index=http_lab sourcetype="_json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
    | stats count by user_agent

This query filters the dataset to HTTP events containing a selected group of user-agent strings that are commonly associated with scripting, automation, or testing tools. It then counts how many times each one appears in the log data.

What I found:  
The results showed `sqlmap/1.5.1` with `79` events, `python-requests/2.25.1` with `78`, `botnet-checker/1.0` with `70`, and `curl/7.68.0` with `69`. This mattered because these user agents stand out from normal browser-based traffic and suggest a stronger possibility of scripted or automated requests. In particular, a tool like `sqlmap` is closely associated with SQL injection testing, while `curl` and `python-requests` are often used in scripts and automation.

### 7. Find Large File Transfers

![Screenshot 10](screenshots/10.png)

For the final task, I looked for HTTP responses involving file transfers larger than 500 KB by using the following query:

    index=http_lab sourcetype="_json" resp_body_len>500000
    | table ts "id.orig_h" "id.resp_h" uri resp_body_len
    | sort -resp_body_len

This query filters the dataset to events where the response body length is greater than `500000` bytes, then displays the timestamp, source IP, destination IP, URI, and response size in a table sorted from largest to smallest. I liked this query because it shifts the focus away from just response codes and user agents and instead looks at traffic volume, which can reveal a different kind of suspicious behavior.

What I found:  
The results showed multiple large HTTP responses, with some entries approaching `2,000,000` bytes in size. Many of the largest transfers were associated with requests to `/index.html`. This mattered because unusually large transfers can point to downloads, bulk content movement, staging activity, or other traffic that deserves closer review, even when the URI itself looks normal.

## Conclusion

This project gave me more hands-on experience using Splunk to ingest, search, and analyze HTTP log data. By working through the dataset, I was able to verify successful ingestion, identify the endpoints generating the most web traffic, measure the volume of server-side errors, examine suspicious user agents, and review large file transfers. Altogether, these tasks helped me build a stronger understanding of how web traffic can be investigated from a security monitoring perspective.

One thing that helped during this project was keeping the HTTP data in its own index instead of mixing it with the SSH logs from the previous lab. Creating the `http_lab` index made the searches easier to manage and reduced confusion when writing queries. This project also reinforced how important it is to check ingestion settings such as source type and index values before doing deeper analysis. If those details are wrong at the start, everything that comes after can become harder to trust.

What I liked about this lab is that it built naturally on the SSH project while still feeling different. The SSH project focused more on authentication activity, while this one moved into web traffic, server errors, suspicious tooling, and response sizes. Because of that, it felt less like repeating the same process and more like expanding the kinds of questions I could answer with Splunk. Overall, this project made the workflow feel more like an actual investigation instead of just a set of isolated searches.
