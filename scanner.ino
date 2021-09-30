#include <Arduino.h>


#include <ESP8266WiFi.h>
#include <WiFiClient.h> 
#include <ESP8266WebServer.h>


WiFiServer server(80);


String header;

IPAddress local_IP(192,168,1,1);
IPAddress subnet(255,255,255,0);


extern "C" {
  #include <user_interface.h>
}

#define DATA_LENGTH           112

#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_PROBE_REQUEST 0x04

bool scanner=true;

int sniffed_p = 0;
int sniffed_added_p = 0;
char nssid[25];


struct RxControl {
 signed rssi:8; 
 unsigned rate:4;
 unsigned is_group:1;
 unsigned:1;
 unsigned sig_mode:2; 
 unsigned legacy_length:12; 
 unsigned damatch0:1;
 unsigned damatch1:1;
 unsigned bssidmatch0:1;
 unsigned bssidmatch1:1;
 unsigned MCS:7;
 unsigned CWB:1; 
 unsigned HT_length:16;
 unsigned Smoothing:1;
 unsigned Not_Sounding:1;
 unsigned:1;
 unsigned Aggregation:1;
 unsigned STBC:2;
 unsigned FEC_CODING:1;
 unsigned SGI:1;
 unsigned rxend_state:8;
 unsigned ampdu_cnt:8;
 unsigned channel:4; 
 unsigned:12;
};


  byte ftype_v[300];
  signed char rssi_v[300];
  byte channel_v[300];
  String addr_v[300];
  String ssid_v[300];



struct SnifferPacket{
    struct RxControl rx_ctrl;
    uint8_t data[DATA_LENGTH];
    uint16_t cnt;
    uint16_t len;
};


static void showMetadata(SnifferPacket *snifferPacket);
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length);
static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data);
static void getMAC(char *addr, uint8_t* data, uint16_t offset);
static void getssid(char *ssid, uint8_t* data, uint16_t offset);
void channelHop();


static void showMetadata(SnifferPacket *snifferPacket) {

  unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];

  unsigned int frameControl1 = snifferPacket->data[0];



if ((frameControl1 == 0x40) || (frameControl1 == 0x50) || (frameControl1 == 0x08)  || (frameControl1 == 0xD4) || (frameControl1 == 0x80))
{
  bool add_record=false;
  
  Serial.print("frame type: ");
  Serial.print(frameControl1, HEX);



  Serial.print(" RSSI: ");
  Serial.print(snifferPacket->rx_ctrl.rssi, DEC);

  Serial.print(" Ch: ");
  Serial.print(wifi_get_channel());

  char addr[] = "00:00:00:00:00:00";
  getMAC(addr, snifferPacket->data, 10);

  char addr_convert[17];
  int ib,ic;



  int poro;
    
  for(ib=0;ib<sniffed_added_p;ib++){

    for(ic=0;ic<=17;ic++){
    addr_convert[ic]=addr_v[ib][ic];
    }
    
    poro = strcmp(addr, addr_convert);
 
    if (poro == 0) {add_record=false;Serial.println();return;}else{add_record=true;}
    
  
    }


    if(sniffed_p==0){
    add_record=true;  
    }
  




    
  Serial.print(" Peer MAC: ");
  Serial.print(addr);



 if(add_record==true){
 addr_v[sniffed_added_p]=addr;
 rssi_v[sniffed_added_p]=snifferPacket->rx_ctrl.rssi;
 sniffed_added_p++; 
 Serial.print(" + ");
 }

 






if (frameControl1 == 0x80) 
{
  getssid(nssid, snifferPacket->data, 38);
  Serial.print(" SSID: ");
  Serial.print(nssid);
   if(add_record==true){
  ssid_v[sniffed_added_p]=nssid;
  ftype_v[sniffed_added_p]=frameControl1;
   }
}
else
{

Serial.print(" other device"); 
 ftype_v[sniffed_added_p]=frameControl1;
 
}






  

  Serial.print(" ");
  Serial.print(String(sniffed_p));

  Serial.println();
  
sniffed_p++;
}
}


static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length) {
  struct SnifferPacket *snifferPacket = (struct SnifferPacket*) buffer;
  
  showMetadata(snifferPacket);
  
}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data) {
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {

if((data[i]) == 0x01) {return;}

Serial.write(data[i]);  




  }
}

static void getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);
}

static void getssid(char *nssid, uint8_t* data, uint16_t offset) {

for (int i1 = 0; i1 < 25; i1++)
  { nssid[i1] = 0x00;}


for(uint16_t iss = 0; sizeof(data); iss++)
 {
  if (data[offset+iss] == 0x01){return;}
 else {nssid[iss]=data[offset+iss];}
 }
}

#define CHANNEL_HOP_INTERVAL_MS   2000
static os_timer_t channelHop_timer;


 #define DISABLE 0
 #define ENABLE  1
void channelHop()
{

  uint8 new_channel = wifi_get_channel() + 1;
  if (new_channel > 13){
      new_channel = 1;    
      scanner=false;      
      }

  
wifi_set_channel(new_channel);
}







static void SwitchtoAPmode() {
  wifi_promiscuous_enable(DISABLE);
delay(50);  
Serial.println("Configuring access point...");
WiFi.mode(WIFI_AP);

delay(500);
WiFi.softAPConfig(local_IP, local_IP, subnet);
WiFi.softAP("Scan","215165");
Serial.print("Soft-AP IP address = ");
Serial.println(WiFi.softAPIP()); 

Serial.println(sniffed_p);

int ia;
for(ia=0;ia<sniffed_p;ia++){

Serial.println(addr_v[ia]);
delay(2);
}


server.begin();
}

void setup() {

  Serial.begin(115200);
  delay(10);
  wifi_set_opmode(STATION_MODE);
  wifi_set_channel(1);
  wifi_promiscuous_enable(DISABLE);
  delay(10);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  delay(10);
  
  wifi_promiscuous_enable(ENABLE);


  os_timer_disarm(&channelHop_timer);
  os_timer_setfn(&channelHop_timer, (os_timer_func_t *) channelHop, NULL);
  os_timer_arm(&channelHop_timer, CHANNEL_HOP_INTERVAL_MS, 1);

addr_v[0]="b0:be:76:21:15:f5";
}

void loop(){
  WiFiClient client = server.available();   

  if (client) {                            
   
    String currentLine = "";               
    while (client.connected()) {            
      if (client.available()) {            
        char c = client.read();             
                          
        header += c;
        if (c == '\n') {                    
       
          if (currentLine.length() == 0) {
       
            client.println("HTTP/1.1 200 OK");
            client.println("Content-type:text/html");
            client.println("Connection: close");
            client.println();
            
     

            
            
            client.println("<!DOCTYPE html><html>");
            client.println("<head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            client.println("<link rel=\"icon\" href=\"data:,\">");
            
            client.println("<style>html { font-family: Helvetica; display: inline-block; margin: 0px auto; text-align: center;}");
            client.println(".button { background-color: #195B6A; border: none; color: white; padding: 16px 40px;");
            client.println("text-decoration: none; font-size: 30px; margin: 2px; cursor: pointer;}");
            client.println(".button2 {background-color: #77878A;}");
            client.println("table, th, td {border: 1px solid black;border-collapse: collapse;}th, td {padding: 5px;text-align: left;}");
            client.println("</style></head>");
           
            client.println("<body><h1>Scanner</h1>");
            client.println("<table style=\"width:100%\">");
            client.println("<tr>");
            client.println("<th>NUM</th>");
            client.println("<th>MAC</th>");
            client.println("<th>SSID</th>");
            client.println("<th>FRAME TYPE</th>");
            client.println("<th>RSSI</th>");
            client.println("</tr>");
            int id;
            for(id=0;id<sniffed_added_p;id++){
              
            client.println("<tr>");

            client.println("<td>");
            client.println(id+1);
            client.println("</td>");

            
            client.println("<td>");
            client.println(addr_v[id]);
            client.println("</td>");
            
            client.println("<td>");
            client.println(ssid_v[id]);
            client.println("</td>");

            client.println("<td>");
            if (ftype_v[id]==0x80){client.println("Beacon");}else {client.println("Device");}
            
            client.println("</td>");


            client.println("<td>");
            client.println(rssi_v[id]);
            client.println("</td>");

            
            client.println("</tr>");
            



             
            }
            
            
            client.println("</table>");
            
            client.println("<p>SCANNED DEVICES: " + String(sniffed_p) + "</p>");
            
            
            client.println("</body></html>");
            
           
            client.println();
           
            break;
          } else { 
            currentLine = "";
          }
        } else if (c != '\r') {  
          currentLine += c;      
        }
      }
    }
    
    header = "";
  
    client.stop();
    Serial.println("client loaded");
  }
 
 
 
 
 
 
 
 
 if (scanner == false)
 {

 os_timer_disarm(&channelHop_timer);
 if (wifi_get_opmode() == 0x01)
 {SwitchtoAPmode();}
 }
 
 delay(10);
}
