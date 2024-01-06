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
const uri = "mongodb+srv://fakhrul:1235@clusterfakhrul.bigkwnk.mongodb.net/?retryWrites=true&w=majority"
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
 *     summary: Authenticate visitor
 *     description: Login with identification number and password for a visitor to view pass
 *     tags: [Visitor]
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
 *         description: Login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
app.post('/retrieveVisitor', async function(req, res){
  const {idNumber, password} = req.body;
  retrieveVisitor(res, idNumber , password);
});

//login as Host
/**
 * @swagger
 * /loginHost:
 *   post:
 *     summary: Authenticate Host
 *     description: Login with identification number and password
 *     tags: [Host]
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
 *         description: Login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
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
 *     summary: Authenticate security personnel
 *     description: Login with identification number and password
 *     tags: [Security]
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
 *         description: Login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
app.post( '/loginSecurity',async function (req, res) {
  let {idNumber, password} = req.body
  const hashed = await generateHash(password);
  await loginSecurity(res, idNumber, hashed)
})

//login as Admin
/**
 * @swagger
 * /loginAdmin:
 *   post:
 *     summary: Authenticate administrator personnel
 *     description: Login with identification number and password
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
 *         description: Login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *       '400':
 *         description: Invalid request body
 *       '401':
 *         description: Unauthorized - Invalid credentials
 *     tags: [Admin]
 */
app.post( '/loginAdmin',async function (req, res) {
  let {idNumber, password} = req.body
  const hashed = await generateHash(password);
  await loginAdmin(res, idNumber, hashed)
})

//register Host
/**
 * @swagger
 * /registerHost:
 *   post:
 *     summary: Register an Host
 *     description: Register a new Host with security role
 *     tags: [Host]
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
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Host registered successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to register an Host
 */
app.post('/registerHost', async function (req, res){
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  jwt.verify(token, privatekey, async function(err, decoded) {
    console.log(decoded)
    if (await decoded.role == "security"){
      const data = req.body
      res.send(
        registerHost(
          data.role,
          data.name,
          data.idNumber,
          data.email,
          data.password,
          data.phoneNumber
        )
      )
    }else{
      console.log("You have no access to register an Host!")
    }
})
})



//View Visitor
/**
 * @swagger
 * /viewVisitor:
 *   post:
 *     summary: "View visitors"
 *     description: "Retrieve visitors based on user role"
 *     tags:
 *       - Host & Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: "Visitors retrieved successfully"
 *       '400':
 *         description: "Invalid token or error in retrieving visitors"
 *       '401':
 *         description: "Unauthorized - Invalid token or insufficient permissions"
 *     consumes:
 *       - "application/json"
 *     produces:
 *       - "application/json"
 *   securityDefinitions:
 *     JWT:
 *       type: "apiKey"
 *       name: "Authorization"
 *       in: "header"
 */
app.post('/viewVisitor', async function(req, res){
  var token = req.header('Authorization').split(" ")[1];
  try {
      var decoded = jwt.verify(token, privatekey);
      console.log(decoded.role);
      res.send(await viewVisitor(decoded.idNumber, decoded.role));
    } catch(err) {
      res.send("Error!");
    }
});

//View Host
/**
 * @swagger
 * /viewHost:
 *   post:
 *     summary: "View hosts"
 *     description: "Retrieve hosts based on user role"
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
 *     JWT:
 *       type: "apiKey"
 *       name: "Authorization"
 *       in: "header"
 *     tags: [Admin]
 */
app.post('/viewHost', async function(req, res){
  var token = req.header('Authorization').split(" ")[1];
  try {
      var decoded = jwt.verify(token, privatekey);
      console.log(decoded.role);
      res.send(await viewHost(decoded.idNumber, decoded.role));
    } catch(err) {
      res.send("Error!");
    }
});

//register visitor
/**
 * @swagger
 * /createpassVisitor:
 *   post:
 *     summary: Create a visitor pass
 *     description: Create a new visitor pass (accessible to Hosts and security personnel)
 *     tags: [Host, Security]
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
 *               age:
 *                 type: number
 *               documentExpiry:
 *                 type: string
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
 *                type: string
 *     responses:
 *       '200':
 *         description: Visitor registered successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to register a visitor
 */
app.post('/createpassVisitor', async function(req, res){
  var token = req.header('Authorization').split(" ")[1];
  let decoded;

  try {
      decoded = jwt.verify(token, privatekey);
      console.log(decoded.role);
  } catch(err) {
      console.log("Error decoding token:", err.message);
      return res.status(401).send("Unauthorized"); // Send a 401 Unauthorized response
  }

  if (decoded && (decoded.role === "Host" || decoded.role === "security")){
      const {
          role, name, idNumber, documentType, gender, birthDate, age, 
          documentExpiry, company, TelephoneNumber, vehicleNumber, 
          category, ethnicity, photoAttributes, passNumber, password
      } = req.body;

      await createpassVisitor(role, name, idNumber, documentType, gender, birthDate, 
                              age, documentExpiry, company, TelephoneNumber, 
                              vehicleNumber, category, ethnicity, photoAttributes, 
                              passNumber, password);
  } else {
      console.log("Access Denied!");
      res.status(403).send("Access Denied"); // Send a 403 Forbidden response
  }
});



//change pass number
/**
 * @swagger
 * /changePassNumber:
 *   post:
 *     summary: Change pass number
 *     description: Change pass number for a user
 *     tags: [Host, Security]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               savedidNumber:
 *                 type: string
 *               newpassNumber:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Pass number changed successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '500':
 *         description: Internal Server Error
 */
app.post('/changePassNumber', async function (req, res){
  const {savedidNumber, newpassNumber} = req.body
  await changePhoneNumber(savedidNumber, newpassNumber)
  res.send(req.body)
})

//delete visitor
/**
 * @swagger
 * /deleteVisitor:
 *   post:
 *     summary: Delete a visitor
 *     description: Delete a visitor by name and ID number
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
 *               name:
 *                 type: string
 *               idNumber:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Visitor deleted successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '500':
 *         description: Internal Server Error
 */
app.post('/deleteVisitor', async function (req, res){
  const {name, idNumber} = req.body
  await deleteVisitor(name, idNumber)
  res.send(req.body)
})

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
async function retrieveVisitor(res, idNumber, password){
  await client.connect();
    const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: idNumber});
    if(exist){
        if(bcrypt.compare(password,await exist.password)){
        console.log("Welcome!");
        token = jwt.sign({ idNumber: idNumber, role: exist.role}, privatekey);
        res.send({
          "Token": token,
          "Visitor Info": exist
        });
        
        res.send(exist);
        await logs(id, exist.name, exist.role);
        }else{
            console.log("Wrong password!")
        }
    }else{
        console.log("Visitor not exist!");
    }
}

//READ(view all visitors)
async function viewVisitor(idNumber, role){
  var exist;
  await client.connect();
  if(role == "Host" || role == "security"){
    exist = await client.db("assignmentCondo").collection("visitor").find({}).toArray();
  }
  else if(role == "visitor"){
    exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: idNumber});
  }
  return exist;
}

//READ(view all visitors)
async function viewHost(idNumber, role){
  var exist;
  await client.connect();
  if(role == "admin"){
    exist = await client.db("assignmentCondo").collection("owner").find({}).toArray();
  }
  else if(role == "security" || role == "visitor"){
    console.log("Visitor not exist!");
  }
  return exist;
}

//READ(login as Host)
async function loginHost(res, idNumber, hashed){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: idNumber });
    if (exist) {
        const passwordMatch = await bcrypt.compare(exist.password, hashed);
        if (passwordMatch) {
            console.log("Login Success!\nRole: "+ exist.role);
            logs(idNumber, exist.name, exist.role);
            const token = jwt.sign({ idNumber: idNumber, role: exist.role }, privatekey);
            res.send("Token: " + token);
        } else {
            console.log("Wrong password!");
        }
    } else {
        console.log("Username not exist!");
    }
}

//READ(login as Security)
async function loginSecurity(res, idNumber, hashed){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("security").findOne({ idNumber: idNumber });
    if (exist) {
        const passwordMatch = await bcrypt.compare(exist.password, hashed);
        if (passwordMatch) {
            console.log("Login Success!\nRole: "+ exist.role);
            logs(idNumber, exist.name, exist.role);
            const token = jwt.sign({ idNumber: idNumber, role: exist.role }, privatekey);
            res.send("Token: " + token);
        } else {
            console.log("Wrong password!");
        }
    } else {
        console.log("Username not exist!");
    }
}

//READ(login as Admin)
async function loginAdmin(res,idNumber, hashed){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("admin").findOne({ idNumber: idNumber });
    if (exist) {
        const passwordMatch = await bcrypt.compare(exist.password, hashed);
        if (passwordMatch) {
            console.log("Login Success!\nRole: "+ exist.role);
            logs(idNumber, exist.name, exist.role);
            const token = jwt.sign({ idNumber: idNumber, role: exist.role }, privatekey);
            res.send("Token: " + token);
        } else {
            console.log("Wrong password!");
        }
    } else {
        console.log("Username not exist!");
    }
}

//CREATE(register Host)
async function registerHost(newrole, newname, newidNumber, newemail, newpassword, newphoneNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("owner").findOne({idNumber: newidNumber})
  if(exist){
    console.log("Host has already registered")
  }else{
    await createListing1(client,
      {
        role: newrole,
        name: newname,
        idNumber: newidNumber,
        email: newemail,
        password: newpassword,
        phoneNumber: newphoneNumber
      }
    );
    console.log("Host registered sucessfully")
  }
}

//CREATE(register Visitor)
async function createpassVisitor(newrole, newname, newidNumber, newdocumentType, newgender, newbirthDate, 
                        newage, newdocumentExpiry, newcompany, newTelephoneNumber, newvehicleNumber,
                        newcategory, newethnicity, newphotoAttributes, newpassNumber, password){
  //TODO: Check if username exist
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: newidNumber})
  //hashed = await bcrypt.hash(password, 10);
  if(exist){
      console.log("Visitor has already registered")
  }else{
      await client.db("assignmentCondo").collection("visitor").insertOne(
        {
          role: newrole,
          name: newname,
          idNumber: newidNumber,
          documentType: newdocumentType,
          gender: newgender,
          birthDate:newbirthDate,
          age: newage,
          documentExpiry: newdocumentExpiry,
          company: newcompany,
          TelephoneNumber: newTelephoneNumber,
          vehicleNumber: newvehicleNumber,
          category: newcategory,
          ethnicity: newethnicity,
          photoAttributes: newphotoAttributes,
          passNumber: newpassNumber,
          password: password 
        }
      );
      console.log("Registered successfully!")
  }
} 

//UPDATE(change pass number)
async function changePhoneNumber(savedidNumber, newpassNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: savedidNumber})
  if(exist){
    await client.db("assignmentCondo").collection("visitor").updateOne({idNumber: savedidNumber}, {$set: {passNumber: newpassNumber}})
    console.log("Visitor's pass number has changed successfuly.")
  }else{
    console.log("The visitor does not exist.")
  }
}

//DELETE(delete visitor)
async function deleteVisitor(oldname, oldidNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({name: oldname})
  if(exist){
    checkidNumber = await exist.idNumber;
    if(oldidNumber == checkidNumber){
      await client.db("assignmentCondo").collection("visitor").deleteOne({name: oldname})
      console.log("Visitor account deleted successfully.")
    }else{
      console.log("ID number is incorrect")
    }
  }else{
    console.log("Visitor does not exist.")
  }
}

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