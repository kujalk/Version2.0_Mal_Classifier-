# Version2.0_Mal_Classifier-
Version 2.0 – Extract the matching signatures from Cuckoo SB analysis report and store it in standalone MongoDB for future references


I have added some modification to my previous script, so now, it can able to automate some other features related to this project


The script will work in the given flow,

1.	Create a workspace directory
 - workspace/Files
- workspace/Results
2.	Copy the malware files to workspace/Files
3.	Get the “sha1” value of the malware file
4.	Compare the “sha1” value with the current malware file name
 - If file name is not matching with “sha1” value, then rename the file to “sha1” value of that file
5.	Send the file name (sha1 value) to MongoDB API to query whether the file record is already existing
6.	If the file is already there in the database, then delete the file in workspace/Files, else send the file to Cuckoo sandbox and get the results and store the results in MongoDB through exposed API and delete the file from the directory workspace/Files

Directory “workspace/Results” is used to store the results of malware files in JSON format


