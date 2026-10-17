Final.py

This app uses a database regular expressions that targets common secret formats. Some of these include AWS, GitHub, Private Keys, Snyk Tokens. It then compiles the regex and validates them. In my example in the video I used a file path which uses os.walk to search the folder and scans each file line by line. Each line of code is compared against all active regular expression patterns. If a match occurs the script takes the file name, line number, matched secret string, and metadata. The findings are logged and shows in a terminal report. 
