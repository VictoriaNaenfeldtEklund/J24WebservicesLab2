## Lab 2 -  Microservices, API Gateway & Authentication

A simple example of a microservice structure where the services are built as images and run in a docker container. 
The clientservice represents an external client and should run in local environment (localhost).

### START MICROSERVICES STEPS:
1. To build the docker images (except clientservice), run the following command standing in the root directory:
   
  ```./build-images.ps1```
   
2. Start the images in a container by running the following command standing in the root directory:

  ```docker-compose up```

3. Run the clientservice application from your local environment.

### NAVIGATE THROUGH APPLICATION:
1. Open a webbrowser and navigate to localhost:7000 which is the clientservice
  
2. The application will redirect you to the authservice on localhost:9000 where you need to login with:

    - username:  user
    - password:  password
   
4. Upon successful login you will be redirected to localhost:7000/ where you can see your accesstoken, username and accesscope.
   From here you can navigate freely to the following services via the available buttons by having a valid accesstoken:

     - jokeservice (to get a random joke)
     - quoteservice (to get a random quote)
