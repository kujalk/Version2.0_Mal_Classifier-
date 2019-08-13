#Purpose : Automation of Malware Analysis
#Tools : Cuckoo SB and MongoDB
#Developer : Janarthanan
#Data: 12/7/2019
#How to Execute: python <script_name>.py <malware folder> <Workspace folder>
#Eg - python script.py /home/user/share/malware /home/user/analysis1


import os,sys,os.path
import time
import requests
import json
import hashlib

#Made change to API port
Cuckoo_Sandbox_API = "http://192.168.2.222:8090"
#path_os="Diff_Mal"
path_os=sys.argv[2]


def get_file_info_from_path(dir,topdown=True):
    dirinfo=[]
    for root, dirs, files in os.walk(dir, topdown):
        for name in files:
            dirinfo.append(os.path.join(root,name))
    return dirinfo

def submit_single_sample_debug(filepath):
    REST_URL = Cuckoo_Sandbox_API + "/tasks/create/file"
    SAMPLE_FILE = filepath

    with open(SAMPLE_FILE, "r") as sample:
        files = {"file": (os.path.basename(filepath), sample)}
        r = requests.post(REST_URL, files=files)

    task_id = r.json()["task_id"][0]
    return task_id

def submit_single_sample(file):
    print "Submit File=", file
    
    try:
       r = requests.post(Cuckoo_Sandbox_API + "/tasks/create/submit", files=[("files", open(file, 'r')),], timeout=300)

    except Exception as e:
       print "Submission of file took more time, therefore terminating the submission of file" 
       return (-500)


    #Added by jana
    if(r.status_code==500):
       print "Internal server error has occured!!!!"
       return (-500)
    
    submit_id = r.json()["submit_id"]
    task_ids = 1

    errors = r.json()["errors"]
    return task_ids



def query_task_status():
    r = requests.get(Cuckoo_Sandbox_API + "/tasks/list")
    tasks=r.json()['tasks']
    reports=[]
    for i in tasks:
        reports.append(i['status'])
    return reports

def submit_samples():
    filepath_list = get_file_info_from_path('data')
    i=1
    ids=[]
    for filepath in filepath_list[:]:
        ids.append(submit_single_sample_debug(filepath))
    print(ids)

def get_report_score(id):
    r=requests.get(Cuckoo_Sandbox_API + "/tasks/report/"+str(id))
    if r.status_code!=200:
        print("fail to get report! code:"+str(r.status_code))
        return 0
    score=r.json()['info']['score']
    return score

def delete_task(ids):
    print("delete:")
    for id in ids:
        print("task:"+str(id))
        r=requests.get(Cuckoo_Sandbox_API + "/tasks/delete/"+str(id))
        errors = r.json()
        print(r.json())


def submit_query_report(file):
    # Submit sample
    id= submit_single_sample(file)

    #Added by jana
    #To handle when internal server error occured in Cuckoo while submitting the file
    #Making the file benign
    if(id==-500):	
      return False,-1
 
#    print ("Submission ID= "+ str(id), end= "")
    print "Submission ID= "+ str(id),

    for count in range(10):
        time.sleep(1)
#        print (".", end= "", flush= True)
        print ".",
        sys.stdout.flush()

    print ("\n")


    # Get Status
    report_array= query_task_status()
    report_count= len(report_array)

    print("Report Count= "+ str(report_count))


    print "Report_Array",

    for count in range(report_count):


       print "["+ str(count)+ "]= "+ str(report_array[count]),

    print("\n")

    # Must ensure all "reports[xx]" are in "reported" state!
    report_counter= report_count- 1
    while (report_counter>= 0):

        print "Report_Array ["+ str(report_counter)+ "]= "+ str(report_array[report_counter]),

        timer=0
        while report_array[report_counter]!= 'reported':
            report_array= query_task_status()

            print ".",
            sys.stdout.flush()

            time.sleep(3)
            timer=timer+1

            if (timer == 400):
               delete_task([id])
               return False,-1

        print ("")

        report_counter-=1

    for count in range(report_count):

        print ">Report_Array ["+ str(count)+ "]= "+ str(report_array[count]),
        print "\t",
    print ("")

    print "ID= "+ str(id),

    score= 0
    report_count= len(report_array)
    if id<= report_count:
         score= get_report_score(id)
    else:
         if report_count> 0:
              score= get_report_score(report_count)

    print("Score= "+ str(score))

    #delete_task([id])

    #Function will return true if score > 5 else return false
    # > 5 means its malicious and < 5 means its benign
    return score> 4.0,id

def submit_json (file_name,id):

	changes=[]
	url="http://192.168.2.222:8090/tasks/report/{}".format(id)
	r=(requests.get(url)).json()

	count=(len(r["signatures"]))

	b=0

	while(b<count):
		changes.append(r["signatures"][b]["description"])	
		b=b+1	

	score=r["info"]["score"]
	d={"name":file_name,"score":score,"signatures":[{'sig':key} for key in changes]}
	h=json.dumps(d,indent=1)
	
	save_name="{0}/workspace/results/{1}.json".format(path_os,file_name)
	
	with open(save_name,'w') as f:
		json.dump(h,f)
		
	headers={'Content-type': 'application/json', 'Accept': 'text/plain'}
	p=requests.post(url="http://193.168.3.194:3000/",data=h,headers=headers)
	print ("Data send")


#To delete the malware file after submission
def delete_file(file_name):
	cmd="rm {0}".format(file_name)
	os.system(cmd)
	print ("File is deleted -> {}".format(file_name))


#To get sha1 of the file and check the file name whether it matches
#If not file will be renamed
#Submit the sha1 name to MongoDB to check whether record exist
#If records exist delete the file and move on to other
#if not proceed
#Return value -> True [proceed] , False [Not proceed with this file]

#file_path=**/workspace/files/ [path_os]
#only_name= i

def file_check(file_path,only_name):

	sha1=hashlib.sha1()

	BUF_SIZE = 65536
	file_before="{0}/workspace/files/{1}".format(file_path,only_name)

	with open(file_before,'rb') as f:
		while True:
			data = f.read(BUF_SIZE)
			if not data:
				break			
			sha1.update(data)

	print("Parameter : "+only_name)
	print("sha1 value is {}".format(sha1.hexdigest()))

	if(sha1.hexdigest()==only_name):
		print ("Original file name and sha1 value are same. [Nothing changed]")
	else:
		cmd="mv {0}/workspace/files/{1} {0}/workspace/files/{2}".format(file_path,only_name,sha1.hexdigest())
		os.system(cmd)
		print("File is renamed to its sha1 value")

	url="http://193.168.3.194:3000/search_file?file={}".format(sha1.hexdigest())
	
	r=requests.get(url)

	response=r.json()
	count=(len(response))

	if(count ==1):
		#The output is similar to list [{"k1":["v1","v2"],"k2":"v2","k3":"v3"}]
		#Convert to JSON string
		j_str=json.dumps(response)

	
		#Convert JSON string to JSON object
		li=json.loads(j_str)

		#li is a type of list convert to dictionary 
		dic=li[0]
	
		print("Name from response: "+dic["name"])

		if(dic["name"]==only_name):
			print("File is already existing in MongoDB")
			delete_file("{0}/workspace/files/{1}".format(file_path,sha1.hexdigest()))
			return "False"

		else:
			print("MongoDB record retrieved. But file names are not matching")
			return "True"
	else:
		print("File is not found in MongoDB. Continuing with Cuckoo Submission....")
		return "True"



	
##### Start of the program
def Classifier():

    #Creating Subdirectory 
    cmd1="mkdir -p {0}/workspace/results {0}/workspace/files".format(path_os)
    os.system(cmd1)

    #Copying the Malware files inot workspace
    cmd2="cp -rf {0}/* {1}/workspace/files/".format(sys.argv[1],path_os)
    os.system(cmd2)


    path="{0}/workspace/files/".format(path_os)

    for i in os.listdir(path):

       file_send="{0}/workspace/files/{1}".format(path_os,i)
       print "Working on file {}".format(i)
       
       #Checking whether the file is eligible for submission
       reply=file_check(path_os,i)

       if(reply=="False"):
            print("Oops!!, this file is not qualified, I am moving to next file\n") 
            continue

       #print("Ya!!!, this file is qualified for submission , I am moving to next file\n") #remove
       #continue #remove
       

       result,id=submit_query_report(file_send)
       
	   
       if id==-1:
           print "File {} is not submitted. Error in submission".format(i)
           continue		   
                         
       else:
               if (result==True):
                   print "File {} is malicious".format(i)
                   submit_json(i,id)
                   delete_task([id])
                   delete_file(file_send)		
			   
               else:
                   print "File {} is not malicious".format(i)
                   submit_json(i,id)
                   delete_task([id])
                   delete_file(file_send)
		   		
    print "Process completed"	

Classifier()
	
