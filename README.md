## DNS proxy server

This is a DNS proxy server with domain blacklist feature to filter unwanted host names resolving

### Limitations
    
 - Maximum blocked domain length defined in server.h file and can be changed
 - Maximum blocked domains amount defined in server.h file and can be changed


### This project requires
 - **C compiler** that supports C 11
 - **CMake** (version 3.28 and higher)
 - **CJson** [(click here to open GitHub repository)](https://github.com/DaveGamble/cJSON)

### How to build

1. Copy this code using git clone
    ```bash
        git clone 
    ```
2. Create and enter a build directory for the server
   ```bash
      mkdir build
   ```
   ```bash
      cd build
   ```

3. Run CMake command specifying directory, where you copied the code
   ```bash     
      cmake <absolute/path/to/testTask1>
   ```
4. Build server using make command in build directory

   ```bash
      make
   ```

5. Run server using next command in this directory.
   Make sure you have configuration file `config.json`
   ```bash
      ./testTAsk1
   ```

### Configuration
 To configure proxy server file `congfig.json` is needed.

 This is an example of configuration file. Field `blacklist_responce` value can be only `REFUSED`, `NOT FOUND`,
 `REDIRECT`.  
```json 
{
  "upstream_dns_ip": "8.8.8.8",
  "port": 1053,
  "blacklist": ["example.com"],
  "blacklist_response": "redirect"
}
```

### How to test
 To test this server I used command `dig`
 This server runs on a local server, so to test I was running following command
 ```bash
  dig @127.0.0.1 -p <server-port>  <site.domain.com>
 ```
 If domain name was found in blacklist, server sends response in accordance with response type defined in configuration 
 file