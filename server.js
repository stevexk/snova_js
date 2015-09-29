/**
 * New node file
 */
var http = require('http');
var url = require("url");
var fs = require('fs');
var net = require('net');
var HashMap = require('./hashmap.js').HashMap;
var ev = require('./event.js');

var VERSION="0.19.3"

var userMap = new HashMap();

function newSession(user, hash){
   var obj = new Object();
   obj.remoteHost = '';
   obj.remotePort = 80;
   obj.sid = hash;
   obj.user = user;
   obj.socket = null;
   obj.sequence = 0;
   obj.cachedEvents = [];
   obj.closed = false;
   obj.close = function() {
      if(null != obj.socket){
        obj.socket.destroy();
        obj.socket = null;
      }
      obj.closed = true;
      if(userMap.has(obj.user)){
       var userSessions = userMap.get(obj.user);
       if(userSessions.has(hash)){
          userSessions.remove(obj.sid);
        }
      }
   }

   obj.endWriter = function(){
      if(null != obj.writer){
        obj.writer.end();
        obj.writer = null;
      }
      if(null != obj.socket){
        obj.socket.pause();
      }
   }

   return obj;
}



function getCreateSession(user, hash, response){
  if(!userMap.has(user)){
    userMap.set(user, new HashMap());
  }
  var userSessions = userMap.get(user);
  if(!userSessions.has(hash)){
    userSessions.set(hash, newSession(user, hash));
  }
  var session = userSessions.get(hash);
  if(null != response)
  {
      session.writer = response;
    }
  return session;
}

function onIndex(request, response) {
   fs.readFile('./index.html', function (err, html) {
    if (err) {
        throw err; 
    }       
    response.writeHead(200, {"Content-Type": "text/html"});
    response.write(html.toString().replace("${version}",VERSION).replace("${version}",VERSION));
    response.end()
});
}

function onDNSQuery(request, response) {
   fs.readFile('./index.html', function (err, html) {
    if (err) {
        throw err; 
    }       
    response.writeHead(200, {"Content-Type": "text/html"});
    response.write(html.toString().replace("${version}",VERSION).replace("${version}",VERSION));
    response.end()
});
}

var HTTP_REQUEST_EVENT_TYPE=1000;
var ENCRYPT_EVENT_TYPE=1501;
var EVENT_TCP_CONNECTION_TYPE = 12000;
var EVENT_USER_LOGIN_TYPE=12002;
var EVENT_TCP_CHUNK_TYPE=12001;
var EVENT_SOCKET_READ_TYPE=13000;

var TCP_CONN_OPENED  = 1;
var TCP_CONN_CLOSED  = 2;

var ENCRYPTER_NONE  = 0;
var ENCRYPTER_SE1  = 1;

function now(){
  return Math.round((new Date()).getTime()/ 1000);
}

function onInvoke(request, response) {
   var length = parseInt(request.headers['content-length']);
   var user = request.headers['usertoken'];
   var miscInfo = request.headers['c4miscinfo'].split('_');
   var ispull = (miscInfo[0] == 'pull');
   var timeout = parseInt(miscInfo[1]);
   var maxread = parseInt(miscInfo[2]);
   var postData = new Buffer(length);
   var recvlen = 0;
   var responsed = false;
   var startTime = now();

   var currentSession = null;

   if(ispull){
       setTimeout(function(){
       if(null != currentSession && currentSession.writer != null){
         currentSession.endWriter();
       }else{
        response.end();
       }
      }, timeout*1000);
   }


   response.writeHead(200, {"Content-Type": "image/jpeg",  "C4LenHeader":1, "Connection":"keep-alive"});
   request.addListener("data", function(chunk) {
      chunk.copy(postData, recvlen, 0);
      recvlen += chunk.length;
    });

   response.on('drain', function () {
      if(null != currentSession && null != currentSession.socket && null != currentSession.writer){
        currentSession.socket.resume();
      }
   });

   request.addListener("end", function() {
      if(recvlen == length && length > 0){
        var readBuf = ev.newReadBuffer(postData);
        var events = ev.decodeEvents(readBuf);
        //console.log("Total events is "+events.length);
        for (var i = 0; i < events.length; i++)
        {
            var evv = events[i];
            //console.log("Decode event " + evv.type + ":" + evv.version + ":" + evv.hash);
            switch(evv.type){
              case EVENT_USER_LOGIN_TYPE:
              {
                if(userMap.has(user)){
                   //userMap.get(user).close();
                }
                userMap.remove(user);
                response.end();
                return;
              }
              case HTTP_REQUEST_EVENT_TYPE:
              {
                var writer = ispull?response:null;
                var session = getCreateSession(user, evv.hash, writer);
                currentSession = session;
                var host = evv.host;
                var port = 80;
                if(evv.method.toLowerCase() == 'connect'){
                   port = 443;
                }
                var ss = host.split(":");
                if(ss.length == 2){
                  host = ss[0];
                  port = parseInt(ss[1]);
                }

                if(null != session.socket && session.remoteHost == host && session.remotePort == port){
                    session.socket.write(evv.rawContent);
                    return;
                }
                session.remoteHost = host;
                session.remotePort = port;
                if(null != session.socket){
                    session.socket.destroy();
                }
                var remoteaddr = host+":" + port;
                //console.log("Connect remote:" + remoteaddr);
                var client = net.connect(port, host ,  function() { 
                    console.log("####Connected:" + remoteaddr + " for hash:" + evv.hash);
                    session.socket = client;
                    session.socket.pause();
                    session.sequence = 0;
                    if(evv.method.toLowerCase() == 'connect'){
                      var established = ev.newEvent(EVENT_TCP_CHUNK_TYPE, 1, session.sid);
                      established.seq = session.sequence++;
                      established.content=new Buffer("HTTP/1.1 200 OK\r\n\r\n");
                      if(null != session.writer)
                      {
                        session.writer.write(ev.encodeChunkTcpChunkEvent(established));
                      }else{
                        session.cachedEvents.push(ev.encodeChunkTcpChunkEvent(established));
                      }
                    }else{
                      session.socket.write(evv.rawContent);
                      //console.log("####writed:" + evv.rawContent.toString());
                    }       
                });
                client.on('data', function(data) {
                    var chunk = ev.newEvent(EVENT_TCP_CHUNK_TYPE, 1, session.sid);
                    chunk.seq = session.sequence++;
                    chunk.content=data;   
                    if(null != session.writer){
                      if(!session.writer.write(ev.encodeChunkTcpChunkEvent(chunk))){
                          session.socket.pause();
                          //session.endWriter(); 
                      }
                    }else{
                      client.pause();
                      session.cachedEvents.push(ev.encodeChunkTcpChunkEvent(chunk));
                      console.log("###Invalid situataion that response writer is null.");
                    }
                });
                client.on('end', function() {
                          
                });
                client.on('error', function(err) {
                   console.log("####Failed to connect:" + remoteaddr + " :" + err);           
                });
                client.on('close', function(had_error) {
                   console.log("####Close connection for " + remoteaddr);    
                   var closed = ev.newEvent(EVENT_TCP_CONNECTION_TYPE, 1, session.sid);  
                   closed.status =  TCP_CONN_CLOSED;
                   closed.addr =  remoteaddr;
                   if(null != session.writer){
                      session.writer.write(ev.encodeChunkConnectionEvent(closed));
                    }else{
                      //cache this event.
                      session.cachedEvents.push(ev.encodeChunkConnectionEvent(closed));
                    } 
                    if(session.closed || remoteaddr == (session.remoteHost + ":" + session.remotePort)){
                      session.endWriter();
                    }              
                });
                response.end();
                break;
              }
              case EVENT_TCP_CONNECTION_TYPE:
              {
                var writer = ispull?response:null;
                var session = getCreateSession(user, evv.hash, writer);
                currentSession = session;
                if(evv.status == TCP_CONN_CLOSED){
                    session.close();
                }
                response.end();
                break;
              }
              case EVENT_TCP_CHUNK_TYPE:
              {
                 var writer = ispull?response:null;
                 var session = getCreateSession(user, evv.hash, writer);
                 currentSession = session;
                 if(null == session.socket){
                   response.end();
                   return;
                 }
                 session.socket.write(evv.content);
                 response.end();
                 break;
              }
              case EVENT_SOCKET_READ_TYPE:
              {
                var writer = ispull?response:null;
                var session = getCreateSession(user, evv.hash, writer);
                currentSession = session;

                var check = function(){
                    for(var i = 0; i < session.cachedEvents.length; i++){
                          writer.write(session.cachedEvents[i]);
                    }
                    session.cachedEvents= [];
                    if(session.closed){
                       session.endWriter();
                       return;
                    }
                    if(session.writer == null){
                       return;
                    }
                     if(session.socket != null)
                     {
                        session.socket.resume();
                     }else{
                        setTimeout(check, 10);
                     }
                   };
    
                check();
                return;
              }
              default:
              {
                console.log("################Unsupported type:" + evv.type);
                response.end();
                break;
              }
            }
        }
      }else{
        console.log("Request not full data ");
      }
   });

}

var handle = {}
handle["/"] = onIndex;
handle["/invoke2"] = onInvoke;

function route(pathname, request, response) {
  if (typeof handle[pathname] === 'function') {
    handle[pathname](request, response);
  } else {
    response.writeHead(404, {"Content-Type": "text/plain"});
    response.end();
  }
}

function onRequest(request, response) {
  var pathname = url.parse(request.url).pathname;
  route(pathname, request, response)
}

var ipaddr  = process.env.OPENSHIFT_NODEJS_IP || "0.0.0.0";
http.createServer(onRequest).listen(process.env.VCAP_APP_PORT ||process.env.OPENSHIFT_NODEJS_PORT || process.env.PORT || 8080, ipaddr);
console.log('Server running at http://127.0.0.1:1337/');