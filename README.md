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

After selecting the file, I followed the upload prompts and reviewed the settings Splunk would use for ingestion. The source type was set to `_json`, which matched the format of the log file. Since I had already completed the SSH log analysis project, I decided to create a separate index called `http_lab` so the HTTP data would stay organized and be easier to search later. Keeping the projects separated made the workflow cleaner and reduced the chance of mixing data sources when writing queries.

### 3. Search the Logs

![Screenshot 4](screenshots/4.png)

To verify that the data was indexed correctly, I ran the following search:

    index=http_lab sourcetype="_json"

This search checks the `http_lab` index for events using the `_json` sourcetype. It is a simple first check, but it matters because it confirms that the log file was uploaded successfully and that the events are actually searchable before moving on to deeper analysis.

What I found:  
The search returned the uploaded HTTP events, which confirmed that the dataset had been ingested correctly and was ready to use. I was also able to see that Splunk was recognizing useful fields in the log data, such as `event_type`, `id.orig_h`, `id.resp_h`, `method`, `status_code`, `uri`, `user_agent`, and `resp_body_len`. Seeing those fields show up correctly told me the file was structured properly enough for the rest of the project to work the way it should.

### 4. Find the Top Endpoints Generating Web Traffic

![Screenshot 5](screenshots/5.png)

To identify the endpoints generating the most web traffic, I used the following query:

    index=http_lab sourcetype="_json"
    | stats count by "id.orig_h"
    | sort -count
    | head 10

This query groups the HTTP events by source IP address, counts how many events came from each endpoint, sorts the counts from highest to lowest, and returns the top 10. I wanted to start here because it gives a quick baseline of which systems in the dataset were the most active before narrowing in on more suspicious behavior.

What I found:  
The results showed the top 10 source IP addresses responsible for the highest volume of HTTP events. The busiest endpoint was `10.0.0.28` with `76` events. It was followed closely by `10.0.0.31` and `10.0.0.42`, both with `73` events, and `10.0.0.27` with `72` events. This was useful because it immediately highlighted which systems were generating the most traffic in the environment. On its own, high traffic is not necessarily suspicious, but it does provide context. If one of these same endpoints also shows up frequently in the server error, suspicious user-agent, or large transfer results, that would make it more interesting from an investigation standpoint.

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
The search returned `285` server error events. After drilling into the result, I was able to look at individual raw events with status codes such as `500` and `503`. That helped confirm that the count was tied to actual HTTP error responses in the data, not just an abstract number on a chart. Looking at the raw events also made this part feel more like actual log analysis and less like just running a query and moving on. A result like this stands out because a high number of 5xx responses can suggest instability on the server side, misconfigurations, or traffic that is causing the application to fail more often than expected.

### 6. Identify Suspicious User Agents

![Screenshot 9](screenshots/9.png)

To identify user agents associated with possible scripted or automated activity, I ran the following query:

    index=http_lab sourcetype="_json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
    | stats count by user_agent

This query filters the dataset to HTTP events containing a selected group of user-agent strings that are commonly associated with scripting, automation, or testing tools. It then counts how many times each one appears in the log data.

What I found:  
The results showed four notable user agents:
- `sqlmap/1.5.1` with `79` events
- `python-requests/2.25.1` with `78` events
- `botnet-checker/1.0` with `70` events
- `curl/7.68.0` with `69` events

This part of the project stood out the most to me because these user agents look very different from standard browser traffic. `sqlmap` is widely known for SQL injection testing, `curl` and `python-requests` are frequently used in scripts and automation, and a name like `botnet-checker` is hard to ignore in a web traffic dataset. That does not automatically mean every one of these requests is malicious, but it does make them worth paying attention to. In a real environment, traffic tied to these user agents would probably deserve a second look, especially if it also lined up with unusual URIs, repeated errors, or large transfers.

### 7. Find Large File Transfers

![Screenshot 10](screenshots/10.png)

For the final task, I looked for HTTP responses involving file transfers larger than 500 KB by using the following query:

    index=http_lab sourcetype="_json" resp_body_len>500000
    | table ts "id.orig_h" "id.resp_h" uri resp_body_len
    | sort -resp_body_len

This query filters the dataset to events where the response body length is greater than `500000` bytes, then displays the timestamp, source IP, destination IP, URI, and response size in a table sorted from largest to smallest. I liked this query because it shifts the focus away from just response codes and user agents and instead looks at traffic volume, which can reveal a different kind of suspicious behavior.

What I found:  
The results showed multiple large HTTP responses, with some entries approaching `2,000,000` bytes in size. The table layout made it easier to compare the systems involved, the requested URI, and the response size across the largest events in the dataset. A lot of the biggest transfers were associated with requests to `/index.html`, which was interesting because it showed that even a normal-looking URI can still be tied to unusually large responses. That is the kind of thing that could easily be overlooked if you only focus on obviously suspicious paths. Looking at response size adds another layer of visibility and helps surface traffic that may deserve closer review, whether it turns out to be normal bulk content or something more unusual.

## Conclusion

This project gave me more hands-on experience using Splunk to ingest, search, and analyze HTTP log data. By working through the dataset, I was able to verify successful ingestion, identify the endpoints generating the most web traffic, measure the volume of server-side errors, examine suspicious user agents, and review large file transfers. 

One thing that helped during this project was keeping the HTTP data in its own index instead of mixing it with the SSH logs from the previous lab. Creating the `http_lab` index made the searches easier to manage and reduced confusion when writing queries. This project also reinforced how important it is to check ingestion settings such as source type and index values before doing deeper analysis. If those details are wrong at the start, everything that comes after can become harder to trust.
