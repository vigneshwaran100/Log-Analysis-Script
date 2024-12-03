Objective
The goal of this assignment is to assess your ability to write a Python script that processes log files to extract and analyze key information. This assignment evaluates your proficiency in file handling, string manipulation, and data analysis, which are essential skills for cybersecurity-related programming tasks.
________________________________________
Core Requirements
Your Python script should implement the following functionalities:
1.	Count Requests per IP Address:
o	Parse the provided log file to extract all IP addresses.
o	Calculate the number of requests made by each IP address.
o	Sort and display the results in descending order of request counts.
o	Example output:
o	IP Address           Request Count
o	192.168.1.1          234
o	203.0.113.5          187
o	10.0.0.2             92
2.	Identify the Most Frequently Accessed Endpoint:
o	Extract the endpoints (e.g., URLs or resource paths) from the log file.
o	Identify the endpoint accessed the highest number of times.
o	Provide the endpoint name and its access count.
o	Example output:
o	Most Frequently Accessed Endpoint:
o	/home (Accessed 403 times)
3.	Detect Suspicious Activity:
o	Identify potential brute force login attempts by:
	Searching for log entries with failed login attempts (e.g., HTTP status code 401 or a specific failure message like "Invalid credentials").
	Flagging IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
o	Display the flagged IP addresses and their failed login counts.
o	Example output:
o	Suspicious Activity Detected:
o	IP Address           Failed Login Attempts
o	192.168.1.100        56
o	203.0.113.34         12
4.	Output Results:
o	Display the results in a clear, organized format in the terminal.
o	Save the results to a CSV file named log_analysis_results.csv with the following structure: 
	Requests per IP: Columns: IP Address, Request Count
	Most Accessed Endpoint: Columns: Endpoint, Access Count
	Suspicious Activity: Columns: IP Address, Failed Login Count
	
