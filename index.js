//express
const express = require('express')
const app = express()
const port = process.env.PORT || 3000;
app.use(express.json())
var jwt = require('jsonwebtoken')

//swagger
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'VMS API',
            version: '1.0.0'
        },
        components: {  // Add 'components' section
          securitySchemes: {  // Define 'securitySchemes'
              bearerAuth: {  // Define 'bearerAuth'
                  type: 'http',
                  scheme: 'bearer',
                  bearerFormat: 'JWT'
              }
          }
      }
    },
    apis: ['./index.js'],
};
const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

//mongoDB
const { MongoClient} = require("mongodb");
const uri = "mongodb://fakhrul:1235@ac-oznfene-shard-00-00.bigkwnk.mongodb.net:27017,ac-oznfene-shard-00-01.bigkwnk.mongodb.net:27017,ac-oznfene-shard-00-02.bigkwnk.mongodb.net:27017/?ssl=true&replicaSet=atlas-mcky5q-shard-0&authSource=admin&retryWrites=true&w=majority"
const  client = new MongoClient(uri)

//bcrypt
const bcrypt = require('bcrypt');
const saltRounds = 10;
var hashed;
//token
var token;
const privatekey = "PRXWGaming";
var checkpassword;

app.use(express.json());

//retrieve Visitor info
/**
 * @swagger
 * /retrieveVisitor:
 *   post:
 *     summary: "Retrieve visitor information"
 *     description: "Retrieve visitor information based on the provided idNumber."
 *     tags:
 *       - Visitor
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               idNumber:
 *                 type: string
 *                 description: "The unique ID number of the visitor."
 *             required:
 *               - idNumber
 *     responses:
 *       '200':
 *         description: "Successfully retrieved visitor information."
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Token:
 *                   type: string
 *                   description: "JWT token for authentication."
 *                 Visitor Info:
 *                   type: object
 *                   description: "Details of the visitor."
 *       '404':
 *         description: "Visitor not found."
 *       '500':
 *         description: "Internal Server Error."
 */
app.post('/retrieveVisitor', async function(req, res) {
  const { idNumber } = req.body;
  retrieveVisitor(res, idNumber); // Only pass idNumber to the function
});

//login as Host
/**
 * @swagger
 * /loginHost:
 *   post:
 *     summary: Login as Host
 *     description: Authenticate and login as a host using the provided ID number and password.
 *     tags:
 *       - Host
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               idNumber:
 *                 type: string
 *                 description: The unique ID number of the host.
 *               password:
 *                 type: string
 *                 description: The password of the host.
 *     responses:
 *       '200':
 *         description: Successfully authenticated and logged in as a host.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Token:
 *                   type: string
 *                   description: JWT token for the authenticated host.
 *       '401':
 *         description: Unauthorized - Incorrect password provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Wrong password!"
 *       '404':
 *         description: Not Found - Host with the provided ID number does not exist.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Username not exist!"
 *       '500':
 *         description: Internal Server Error - Failed to authenticate due to server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Internal Server Error!"
 */
app.post( '/loginHost',async function (req, res) {
  let {idNumber, password} = req.body;
  const hashed = await generateHash(password);
  await loginHost(res, idNumber, hashed)
})

//login as Security
/**
 * @swagger
 * /loginSecurity:
 *   post:
 *     summary: Login as Security
 *     description: Authenticate and login as a security personnel.
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               idNumber:
 *                 type: string
 *                 description: The unique ID number of the security personnel.
 *               password:
 *                 type: string
 *                 description: The password associated with the security personnel's account.
 *     responses:
 *       '200':
 *         description: Successfully authenticated. Returns a JWT token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZEN..."
 *       '401':
 *         description: Unauthorized - Incorrect password.
 *       '404':
 *         description: Not Found - Security personnel with the provided ID number does not exist.
 *       '500':
 *         description: Internal Server Error - Failed to authenticate due to server error.
 */
app.post('/loginSecurity', async function (req, res) {
  let { idNumber, password } = req.body;
  const hashed = await generateHash(password);
  await loginSecurity(res, idNumber, hashed);
});

//login as Admin
/**
 * @swagger
* /loginAdmin:
*   post:
  *     summary: Admin Login
  *     description: Authenticate as an administrator and receive a JWT token.
  *     tags: [Admin]
  *     requestBody:
  *       required: true
  *       content:
  *         application/json:
  *           schema:
  *             type: object
  *             properties:
  *               idNumber:
  *                 type: string
  *               password:
  *                 type: string
  *     responses:
  *       '200':
  *         description: Login successful.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: true
  *                 message:
  *                   type: string
  *                   example: Login Success!
  *                 token:
  *                   type: string
  *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  *       '401':
  *         description: Unauthorized - Wrong password.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: false
  *                 message:
  *                   type: string
  *                   example: Wrong password!
  *       '404':
  *         description: Not Found - Username not exist.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: false
  *                 message:
  *                   type: string
  *                   example: Username not exist!
  *       '500':
  *         description: Internal server error occurred.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: false
  *                 message:
  *                   type: string
  *                   example: An error occurred.
 */
app.post('/loginAdmin', async function (req, res) {
  let { idNumber, password } = req.body;
  const hashed = await generateHash(password);
  await loginAdmin(res, idNumber, hashed);
});


//register Host
/**
 * @swagger
 * /registerHost:
 *   post:
 *     summary: Register a Host
 *     description: Register a new host if the requester has security access.
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *                 description: Role of the host.
 *               name:
 *                 type: string
 *                 description: Name of the host.
 *               idNumber:
 *                 type: string
 *                 description: ID number of the host.
 *               email:
 *                 type: string
 *                 description: Email address of the host.
 *               password:
 *                 type: string
 *                 description: Password of the host.
 *               phoneNumber:
 *                 type: string
 *                 description: Phone number of the host.
 *     responses:
 *       '200':
 *         description: Host registered successfully.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Host registered successfully"
 *       '403':
 *         description: Forbidden - User does not have the necessary permissions.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "You have no access to register a Host!"
 *       '409':
 *         description: Conflict - Host with the provided ID number already exists.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Host has already registered"
 *       '500':
 *         description: Internal Server Error - Failed to register the host due to server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Internal Server Error!"
 */
app.post('/registerHost', async function (req, res) {
  let header = req.headers.authorization;

  // Check if Authorization header exists and contains a token
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).send("Unauthorized"); // Send unauthorized error in response
  }

  let token = header.split(' ')[1];
  
  jwt.verify(token, privatekey, async function(err, decoded) {
    if (err) {
      return res.status(401).send("Unauthorized"); // Send unauthorized error in response if JWT verification fails
    }
    
    registerHost(decoded, req.body, res);
  });
});


//register Host without security approval
/**
 * @swagger
 * /registertestHost:
 *   post:
 *     summary: Register a test host
 *     description: Endpoint to register a test host. Checks if the host with the provided ID number already exists and registers if not.
 *     tags:
 *       - Host & Security & Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *               name:
 *                 type: string
 *               idNumber:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               phoneNumber:
 *                 type: string
 *     responses:
 *       200:
 *         description: Host registered successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Host registered successfully
 *       400:
 *         description: Host with the provided ID number already exists.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Host has already registered
 *       500:
 *         description: Internal server error occurred.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Internal server error occurred.
 */
app.post('/registertestHost', async function (req, res) {
  const data = req.body;
  await registertestHost(
    data.role,
    data.name,
    data.idNumber,
    data.email,
    data.password,
    data.phoneNumber,
    res  // Pass the response object to the function
  );
});

//View Visitor
/**
 * @swagger
 * /viewVisitor:
 *   post:
 *     summary: View visitor details
 *     description: View details of a visitor based on the provided token (accessible to authorized users)
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Visitor details retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Token:
 *                   type: string
 *                   description: Authorization token
 *                 VisitorInfo:
 *                   type: object
 *                   properties:
 *                     idNumberHost:
 *                       type: string
 *                       description: ID number of the host
 *                     timeOfVisit:
 *                       type: string
 *                       description: Time of the visit
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to view visitor details
 *       '404':
 *         description: Not Found - Visitor not found
 */
app.post('/viewVisitor', async function(req, res) {
  const header = req.header('Authorization');
  
  // Check if Authorization header exists
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).send("Invalid or no token"); // Send message if token is missing or malformed
  }

  const token = header.split(" ")[1];
  
  try {
    const decoded = jwt.verify(token, privatekey);
    return await viewVisitor(decoded.idNumber, decoded.role, res);
  } catch(err) {
    return res.status(401).send("Unauthorized"); // Send unauthorized error in response
  }
});

//View Host
/**
 * @swagger
 * /viewHost:
 *   post:
 *     summary: "View hosts"
 *     description: "Retrieve hosts based on user role"
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: "Hosts retrieved successfully"
 *       '400':
 *         description: "Invalid token or error in retrieving hosts"
 *       '401':
 *         description: "Unauthorized - Invalid token or insufficient permissions"
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 *   securityDefinitions:
 *     bearerAuth:
 *       type: "apiKey"
 *       name: "Authorization"
 *       in: "header"
 */
app.post('/viewHost', async function(req, res){
  const header = req.header('Authorization');
  
  // Check if Authorization header exists
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).send("Invalid or no token"); // Send message if token is missing or malformed
  }

  const token = header.split(" ")[1];
  
  try {
    const decoded = jwt.verify(token, privatekey);
    return res.send(await viewHost(decoded.idNumber, decoded.role)); // Removed 'res' as it's not needed for the function
  } catch(err) {
    return res.status(401).send("Invalid token"); // Send "Invalid token" instead of "Unauthorized"
  }
});


//issue pass visitor
/**
 * @swagger
 * /issuepassVisitor:
 *   post:
 *     summary: Issue a visitor pass
 *     description: Issue a new visitor pass (accessible to Hosts and security personnel)
 *     tags:
 *       - Host & Security
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               role:
 *                 type: string
 *               name:
 *                 type: string
 *               idNumber:
 *                 type: string
 *               documentType:
 *                 type: string
 *               gender:
 *                 type: string
 *               birthDate:
 *                 type: string
 *                 format: date
 *               age:
 *                 type: number
 *               documentExpiry:
 *                 type: string
 *                 format: date
 *               company:
 *                 type: string
 *               TelephoneNumber:
 *                 type: string
 *               vehicleNumber:
 *                 type: string
 *               category:
 *                 type: string
 *               ethnicity:
 *                 type: string
 *               photoAttributes:
 *                 type: string
 *               passNumber:
 *                 type: string
 *               password:
 *                 type: string
 *               idNumberHost:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Visitor pass issued successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to issue a visitor pass
 *       '500':
 *         description: Internal Server Error - An error occurred during processing
 */
app.post('/issuepassVisitor', async function(req, res){
  const header = req.header('Authorization');
  
  // Check if Authorization header exists
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).send("Invalid or no token"); // Send message if the token is missing or malformed
  }

  const token = header.split(" ")[1];
  let decoded;

  try {
    decoded = jwt.verify(token, privatekey);
    console.log(decoded.role);
  } catch(err) {
    console.log("Error decoding token:", err.message);
    return res.status(401).send("Unauthorized"); // Send a 401 Unauthorized response
  }

  if (decoded && (decoded.role === "Host" || decoded.role === "security")) {
    const {
      role, name, idNumber, documentType, gender, birthDate, age, 
      documentExpiry, company, TelephoneNumber, vehicleNumber, 
      category, ethnicity, photoAttributes, passNumber, password, idNumberHost
    } = req.body;

    try {
      await issuepassVisitor(role, name, idNumber, documentType, gender, birthDate, 
                              age, documentExpiry, company, TelephoneNumber, 
                              vehicleNumber, category, ethnicity, photoAttributes, 
                              passNumber, password, idNumberHost, res);
    } catch (error) {
      console.log(error.message);
      res.status(500).send("An error occurred");
    }
  } else {
    console.log("Access Denied!");
    res.status(403).send("Access Denied"); // Send a 403 Forbidden response
  }
});

/**
 * @swagger
 * /retrieveHostContact:
 *   post:
 *     summary: Retrieve host contact number
 *     description: Retrieve the contact number of the host from the given visitor pass (accessible to security personnel)
 *     tags:
 *       - Security 
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               visitorPassNumber:
 *                 type: string
 *                 description: Visitor pass number to retrieve host contact
 *     responses:
 *       '200':
 *         description: Host contact retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 phoneNumber:
 *                   type: string
 *                   description: Contact number of the host
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to retrieve host contact
 *       '404':
 *         description: Not Found - Visitor pass or host not found
 */
app.post('/retrieveHostContact', async function(req, res) {
  const token = req.header('Authorization') ? req.header('Authorization').split(" ")[1] : null;

  if (!token) {
    return res.status(400).send("Invalid or no token"); // Send "Invalid or no token" response
  }

  try {
    const decoded = jwt.verify(token, privatekey);

    if (decoded && decoded.role === "security") {
      const visitorPassNumber = req.body;

      try {
        const hostContactResponse = await retrieveHostContact(visitorPassNumber.visitorPassNumber);
        // Send the host contact number in the response body
        res.status(200).send({ phoneNumber: hostContactResponse.phoneNumber });
      } catch (error) {
        // Handle errors such as host not found
        res.status(404).send(error.message);
      }
    } else {
      // Send "Access Denied" response
      res.status(403).send("Access Denied");
    }
  } catch (err) {
    // Send "Unauthorized" response
    res.status(401).send("Unauthorized");
  }
});



// Manage User Role
/**
 * @swagger
* /manageRole:
*   post:
  *     summary: Manage user role
  *     description: Manage the role of a user by updating the role associated with the provided ID number (accessible to administrators).
  *     tags: [Admin]
  *     security:
  *       - bearerAuth: []
  *     requestBody:
  *       required: true
  *       content:
  *         application/json:
  *           schema:
  *             type: object
  *             properties:
  *               idNumber:
  *                 type: string
  *               role:
  *                 type: string
  *     responses:
  *       '200':
  *         description: Role managed successfully.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: true
  *                 message:
  *                   type: string
  *                   example: Role managed successfully!
  *       '400':
  *         description: Bad Request - Role management failed.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: false
  *                 message:
  *                   type: string
  *                   example: Username not in the database!
  *       '401':
  *         description: Unauthorized - Invalid or missing token.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: false
  *                 message:
  *                   type: string
  *                   example: Unauthorized
  *       '403':
  *         description: Forbidden - User does not have the necessary permissions.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: false
  *                 message:
  *                   type: string
  *                   example: Access Denied
  *       '500':
  *         description: Internal server error occurred.
  *         content:
  *           application/json:
  *             schema:
  *               type: object
  *               properties:
  *                 success:
  *                   type: boolean
  *                   example: false
  *                 message:
  *                   type: string
  *                   example: An error occurred.
 */
app.post('/manageRole', async function (req, res){
  var token;

  // Check if Authorization header is present and contains the Bearer token
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  } else {
    // Send a 400 Bad Request response if no token is found
    return res.status(400).json({ success: false, message: "Invalid or no token provided" });
  }

  let decoded;

  try {
    decoded = jwt.verify(token, privatekey);
  } catch(err) {
    console.log("Error decoding token:", err.message);
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  if (decoded && (decoded.role === "admin")){
    const { idNumber, role } = req.body;

    try {
      const result = await manageRole(idNumber, role);
      
      if (result.success) {
        res.status(200).json({ success: true, message: result.message });
      } else {
        res.status(400).json({ success: false, message: result.message });
      }
    } catch (error) {
      console.log(error.message);
      res.status(500).json({ success: false, message: "An error occurred" });
    }
  } else {
    console.log("Access Denied!");
    res.status(403).json({ success: false, message: "Access Denied" });
  }
});


// Express route for authenticated host to delete their assigned visitor
/**
 * @swagger
 * /deleteVisitor:
 *   delete:
 *     summary: "Delete a visitor"
 *     description: "Authenticated Host can delete a visitor using the visitor's pass number."
 *     tags: [Host]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               passNumber:
 *                 type: string
 *                 description: "Visitor's pass number to be deleted"
 *             required:
 *               - passNumber
 *     responses:
 *       '200':
 *         description: "Visitor deleted successfully"
 *       '401':
 *         description: "Unauthorized - Invalid or missing token"
 *       '403':
 *         description: "Access Denied - User is not a Host"
 *       '404':
 *         description: "Visitor not found"
 *       '500':
 *         description: "Internal Server Error"
 */
app.delete('/deleteVisitor', async (req, res) => {
  const token = req.header('Authorization') ? req.header('Authorization').split(" ")[1] : null;

  if (!token) {
    return res.status(400).send("Invalid or no token"); // Send "Invalid or no token" response
  }

  try {
    const decoded = jwt.verify(token, privatekey);

    if (decoded && decoded.role === "Host") {
      const { passNumber } = req.body;

      try {
        await deleteVisitor(decoded.idNumber, passNumber);
        // Send success message in the response body
        res.status(200).send("Visitor deleted successfully");
      } catch (error) {
        // Handle errors such as visitor not found or access denied
        res.status(error.statusCode).send(error.message);
      }
    } else {
      // Send "Access Denied" response
      res.status(403).send("Access Denied");
    }
  } catch (err) {
    // Send "Unauthorized" response
    res.status(401).send("Unauthorized");
  }
});


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

//////////FUNCTION//////////

async function logs(idNumber, name, role){
  // Get the current date and time
  const currentDate = new Date();

  // Format the date
  const formattedDate = currentDate.toLocaleDateString(); // Format: MM/DD/YYYY

  // Format the time
  const formattedTime = currentDate.toLocaleTimeString(); // Format: HH:MM:SS
  await client.connect()
  client.db("assignmentCondo").collection("logs").insertOne({
      idNumber: idNumber,
      name: name,
      Type: role,
      date: formattedDate,
      entry_time: formattedTime,
      exit_time: "pending"
  })
}

//CREATE(createListing for Host)
async function createListing1(client, newListing){
  const result = await client.db("assignmentCondo").collection("owner").insertOne(newListing);
  console.log(`New listing created with the following id: ${result.insertedId}`);
}

//CREATE(createListing for visitor)
async function createListing2(client, newListing){
  const result = await client.db("assignmentCondo").collection("visitor").insertOne(newListing);
  console.log(`New listing created with the following id: ${result.insertedId}`);
}

//READ(retrieve pass as visitor)
async function retrieveVisitor(res, idNumber) {
  await client.connect();
  
  try {
    const exist = await client.db("assignmentCondo").collection("visitor").findOne({ idNumber: idNumber });
    
    if (exist) {
      const { idNumberHost, timeOfVisit } = exist; // Extract idNumberHost and timeOfVisit
      res.status(200).send({
        "Visitor Info": {
          idNumberHost: idNumberHost,
          timeOfVisit: timeOfVisit
        }
      });
      await logs(idNumber, exist.name, exist.role); // Assuming the logs function is correct.
    } else {
      res.status(404).send("Visitor not found!"); // Send visitor not found message in response
    }
  } catch (error) {
    console.error("Error retrieving visitor:", error);
    res.status(500).send("Internal Server Error"); // Handle any unexpected errors.
  }
}


//READ(view all visitors)
async function viewVisitor(idNumberHost, role, res) {
  await client.connect();
  let visitors;

  if (role === "Host") {
    visitors = await client.db("assignmentCondo").collection("visitor").find({ idNumberHost: idNumberHost }).toArray();

    if (visitors.length === 0) {
      return res.status(404).send("No visitors found for this host."); // Send not found error in response
    }

    return res.status(200).send(visitors); // Send existing visitors' details in response
  } 
  else if (role === "visitor" || role === "security") {
    return res.status(403).send("Forbidden! You don't have permission to view this information."); // Send forbidden error in response
  } 
  else {
    return res.status(400).send("Invalid role!"); // Send bad request error in response for an invalid role
  }
}

//READ(view all visitors)
async function viewHost(idNumber, role, res){ // Add res as a parameter
  var exist;
  await client.connect();
  
  if(role === "admin"){
    exist = await client.db("assignmentCondo").collection("owner").find({}).toArray();
  }
  else if(role === "security" || role === "visitor"){
    res.status(403).send("Forbidden! You don't have permission to access this."); // Send Forbidden status if role is not admin
  }
  
  return exist;
}

//READ(login as Host)
async function loginHost(res, idNumber, hashed) {
  await client.connect();
  const exist = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: idNumber });
  
  if (exist) {
    const passwordMatch = await bcrypt.compare(exist.password, hashed);
    if (passwordMatch) {
      console.log("Login Success!\nRole: " + exist.role);
      logs(idNumber, exist.name, exist.role);
      const token = jwt.sign({ idNumber: idNumber, role: exist.role }, privatekey);
      res.send("Token: " + token);
    } else {
      // Send password mismatch error in response
      res.status(401).send("Wrong password!");
    }
  } else {
    // Send username not found error in response
    res.status(404).send("Username not exist!");
  }
}


// READ (login as Security)
async function loginSecurity(res, idNumber, hashed) {
  await client.connect();
  const exist = await client.db("assignmentCondo").collection("security").findOne({ idNumber: idNumber });
  
  if (exist) {
    const passwordMatch = await bcrypt.compare(exist.password, hashed);
    if (passwordMatch) {
      console.log("Login Success!\nRole: " + exist.role);
      logs(idNumber, exist.name, exist.role);
      const token = jwt.sign({ idNumber: idNumber, role: exist.role }, privatekey);
      res.send("Token: " + token);
    } else {
      // Send password mismatch error in response
      res.status(401).send("Wrong password!");
    }
  } else {
    // Send username not found error in response
    res.status(404).send("Username not exist!");
  }
}

async function loginAdmin(res, idNumber, hashed) {
  await client.connect();

  try {
    const exist = await client.db("assignmentCondo").collection("admin").findOne({ idNumber: idNumber });

    if (exist) {
      const passwordMatch = await bcrypt.compare(exist.password, hashed);

      if (passwordMatch) {
        console.log("Login Success!\nRole: " + exist.role);
        logs(idNumber, exist.name, exist.role);
        const token = jwt.sign({ idNumber: idNumber, role: exist.role }, privatekey);
        res.status(200).json({ success: true, message: "Login Success!", token: token });
      } else {
        console.log("Wrong password!");
        res.status(401).json({ success: false, message: "Wrong password!" });
      }
    } else {
      console.log("Username not exist!");
      res.status(404).json({ success: false, message: "Username not exist!" });
    }
  } catch (error) {
    console.error("Error:", error.message);
    res.status(500).json({ success: false, message: "An error occurred" });
  } finally {
    client.close();
  }
}


//CREATE(register Host)
async function registerHost(decoded, data, res) {
  if (decoded && decoded.role === "security") {
    await client.connect();
    const exist = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: data.idNumber });

    if (exist) {
      res.status(400).send("Host has already registered"); // Send message in response
    } else {
      await createListing1(client, {
        role: data.role,
        name: data.name,
        idNumber: data.idNumber,
        email: data.email,
        password: data.password,
        phoneNumber: data.phoneNumber
      });
      res.status(200).send("Host registered successfully"); // Send message in response
    }
  } else {
    res.status(403).send("You have no access to register a Host!"); // Send forbidden message
  }
}

//CREATE(register Host)
async function registertestHost(newrole, newname, newidNumber, newemail, newpassword, newphoneNumber, res) {
  await client.connect();
  const exist = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: newidNumber });

  if (exist) {
    res.status(400).send("Host has already registered"); // Send message in response
  } else {
    await createListing1(client, {
      role: newrole,
      name: newname,
      idNumber: newidNumber,
      email: newemail,
      password: newpassword,
      phoneNumber: newphoneNumber
    });
    res.status(200).send("Host registered successfully"); // Send message in response
  }
}

//CREATE(register Visitor)
async function issuepassVisitor(newrole, newname, newidNumber, newdocumentType, newgender, newbirthDate, 
  newage, newdocumentExpiry, newcompany, newTelephoneNumber, newvehicleNumber,
  newcategory, newethnicity, newphotoAttributes, newpassNumber, password, idNumberHost, res) {
  // TODO: Check if username exists
  await client.connect();
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({ idNumber: newidNumber });

  if (exist) {
    res.status(400).send("Visitor has already registered"); // Send a 400 Bad Request status
  } else {
    const currentDate = new Date(); // Get the current date and time
    await client.db("assignmentCondo").collection("visitor").insertOne({
      role: newrole,
      name: newname,
      idNumber: newidNumber,
      documentType: newdocumentType,
      gender: newgender,
      birthDate: newbirthDate,
      age: newage,
      documentExpiry: newdocumentExpiry,
      company: newcompany,
      TelephoneNumber: newTelephoneNumber,
      vehicleNumber: newvehicleNumber,
      category: newcategory,
      ethnicity: newethnicity,
      photoAttributes: newphotoAttributes,
      passNumber: newpassNumber,
      password: password,
      idNumberHost: idNumberHost,
      timeOfVisit: currentDate // Add the current date and time to the document
    });

    res.status(200).send("Registered successfully!"); // Send a 200 OK status
  }
}

async function retrieveHostContact(visitorPassNumber) {
  try {
    await client.connect();

    const visitor = await client.db("assignmentCondo").collection("visitor").findOne({ passNumber: visitorPassNumber });
    
    if (visitor) {
      const hostIdNumber = visitor.idNumberHost;
      const host = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: hostIdNumber });

      if (host) {
        return { phoneNumber: host.phoneNumber };
      } else {
        throw new Error("Host not found.");
      }
    } else {
      throw new Error("Visitor not found.");
    }
  } catch (error) {
    console.error("Error retrieving host contact:", error);
    throw error;
  }
}

async function manageRole(idNumber, role) {
  try {
    await client.connect();
    
    const ownerCollection = client.db("assignmentCondo").collection("owner");
    const desiredCollection = client.db("assignmentCondo").collection("security");

    const user = await ownerCollection.findOne({ idNumber: idNumber });

    if (user) {
      // Update the role in the "owner" collection
      await ownerCollection.updateOne({ idNumber: idNumber }, { $set: { role: role } });
      console.log("Role managed successfully!");

      // Insert the user's data into the desired collection if it doesn't exist there
      const userInDesiredCollection = await desiredCollection.findOne({ idNumber: idNumber });

      if (!userInDesiredCollection) {
        await desiredCollection.insertOne(user);
        console.log("User data added to the desired collection.");
      }

      // Delete the user from the old collection
      await ownerCollection.deleteOne({ idNumber: idNumber });
      console.log("User data deleted from the old collection.");

      // Send a success response to the client
      return { success: true, message: "Role managed successfully!" };
    } else {
      // Send an error response to the client
      return { success: false, message: "Username not in the database!" };
    }
  } catch (error) {
    // Handle other errors
    console.log("Error:", error.message);
    // Send an error response to the client
    return { success: false, message: "An error occurred." };
  } finally {
    client.close();
  }
}

// Function to delete assigned visitor based on passNumber
async function deleteVisitor(hostIdNumber, passNumber) {
  try {
    await client.connect();

    // Check if the visitor exists and is assigned to the requesting host
    const visitor = await client.db("assignmentCondo").collection("visitor").findOne({
      passNumber: passNumber,
      idNumberHost: hostIdNumber
    });

    if (visitor) {
      // Delete the visitor
      await client.db("assignmentCondo").collection("visitor").deleteOne({ passNumber: passNumber });
    } else {
      throw { message: "Visitor not found or access denied.", statusCode: 404 };
    }
  } catch (error) {
    console.error("Error deleting assigned visitor:", error);
    throw error;
  }
}


//DELETE(delete visitor)
//async function deleteVisitor(oldname, oldidNumber){
//  await client.connect()
//  const exist = await client.db("assignmentCondo").collection("visitor").findOne({name: oldname})
//  if(exist){
//    checkidNumber = await exist.idNumber;
//    if(oldidNumber == checkidNumber){
//      await client.db("assignmentCondo").collection("visitor").deleteOne({name: oldname})
//       console.log("Visitor account deleted successfully.")
//     }else{
//      console.log("ID number is incorrect")
//     }
//   }else{
//     console.log("Visitor does not exist.")
//   }
// }

//Generate hash password
async function generateHash(password){
  const saltRounds = 10
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
}

//Verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'PRXgaming', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }
    res.user = decoded;
    next();
  });
}