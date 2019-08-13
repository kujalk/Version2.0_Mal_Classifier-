/*
 *Developer - Janarthanan
 *Purpose - RestFul API for PDF Duzzing tool to retrieve malware details
 */ 

var express = require('express');
var app = express();
var cors= require('cors');
var path = require('path');
var bodyParser = require('body-parser');
var MongoClient = require('mongodb').MongoClient
var db;

app.use(cors());
//Establish Connection
MongoClient.connect('mongodb://localhost:27017/results', function (err, database) {
   if (err) 
   	throw err
   else
   {
	db = database;
	console.log('Connected to MongoDB');
	//Start app only after connection is ready
	app.listen(3000,'193.168.3.194');
        console.log('I am now listening....')
   }
 });

app.use(bodyParser.json())

app.post('/', function(req, res) {
   // Insert JSON straight into MongoDB
  db.collection('post_data').insert(req.body, function (err, result) {
      if (err)
         res.send('Error');
      else
        res.send('Success');

  });
});

app.get('/signatures', function(req, res) {
  //Get the unique signatures

  db.collection('post_data').distinct("signatures.sig",function(err, result) {

   if (err){
      res.send('Error');
      console.log("Error in retrieving unique signatures");
   }
   else{
      res.send(result)
       console.log("Response send via ->/signatures API");
     }
});
});


app.get('/files_sig', function(req, res) {
  //Get the files that are matching particular  signatures pattern
  //Parameter is passed with URL

  //Extracting the parameter
  var parameter=req.query.file

  //Adding the pattern as like 
  var pat="/"+parameter+"/"

  //converting string to object
  var pattern=eval(pat);

  console.log(typeof pattern)
  var query={};
  console.log("Parameter is ->"+pattern);
  query['signatures.sig'] = pattern
  //query={'signatures.sig': /RWX/}
  
   db.collection('post_data').find(query,{name:1,_id: 0}).toArray(function(err, result) {
  
   if (err){
      res.send('Error');
      console.log("Error in retrieving unique signatures");
   }
   else{
      
      res.send(JSON.stringify(result));
      console.log("Response send via ->/signatures API for the parameter "+parameter);
    }
  
  });
  });


app.get('/search_file', function(req, res) {
  // search file to obtain their signatures
  // Parameter is passed with URL
  
  //Extracting the parameter
    var file_name=req.query.file
 
  //Adding the pattern as like
    var pat="/"+file_name+"/"
 
  //converting string to object
    var pattern=eval(pat);
  
    console.log(typeof pattern)
    var query={};
    console.log("Parameter is ->"+pattern);
    query['name'] = pattern
                  
  
    db.collection('post_data').find(query,{_id: 0}).toArray(function(err, result) {
  
    if (err){
         res.send('Error');
         console.log("Error in retrieving information related to the file");
     }
    else{
  
         res.send(JSON.stringify(result));
         console.log("Response send via ->/search_file API for the parameter "+file_name);
        }
  
   });
   });


