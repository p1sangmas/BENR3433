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
const uri = "mongodb+srv://fakhrul:1235@clusterfakhrul.bigkwnk.mongodb.net/"
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

//login as Visitor
/**
 * @swagger
 * /loginVisitor:
 *   post:
 *     summary: Authenticate visitor
 *     description: Login with identification number and password for a visitor
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
app.post('/loginVisitor', async function(req, res){
  const {idNumber, password} = req.body;
  loginVisitor(res, idNumber , password);
});

//login as Owner
/**
 * @swagger
 * /loginOwner:
 *   post:
 *     summary: Authenticate owner
 *     description: Login with identification number and password
 *     tags: [Owner]
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
app.post( '/loginOwner',async function (req, res) {
  let {idNumber, password} = req.body;
  const hashed = await generateHash(password);
  await loginOwner(res, idNumber, hashed)
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

//register Owner
/**
 * @swagger
 * /registerOwner:
 *   post:
 *     summary: Register an owner
 *     description: Register a new owner with security role
 *     tags: [Owner]
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
 *         description: Owner registered successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to register an owner
 */
app.post('/registerOwner', async function (req, res){
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  jwt.verify(token, privatekey, async function(err, decoded) {
    console.log(decoded)
    if (await decoded.role == "security"){
      const data = req.body
      res.send(
        registerOwner(
          data.role,
          data.name,
          data.idNumber,
          data.email,
          data.password,
          data.phoneNumber
        )
      )
    }else{
      console.log("You have no access to register an owner!")
    }
})
})



//view visitor 
/**
 * @swagger
 * /viewVisitor:
 *   get:
 *     summary: View list of visitors
 *     description: Retrieve a list of visitors (accessible to owners and security personnel)
 *     tags: [Owner, Security, Visitor]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: List of visitors retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to view visitors
 */
app.get('/viewVisitor', async function(req, res){
  await client.connect()
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  jwt.verify(token, privatekey);
    console.log(decoded.role);
      res.send(await viewVisitor(decoded.idNumber, decoded.role));
  }
);

//register visitor
/**
 * @swagger
 * /registerVisitor:
 *   post:
 *     summary: Register a visitor
 *     description: Register a new visitor (accessible to owners and security personnel)
 *     tags: [Owner]
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
 *     responses:
 *       '200':
 *         description: Visitor registered successfully
 *       '401':
 *         description: Unauthorized - Invalid or missing token
 *       '403':
 *         description: Forbidden - User does not have access to register a visitor
 */
app.post('/registerVisitor', async function (req, res) {
  let header = req.headers.authorization;
  let token = header.split(' ')[1];
  
  jwt.verify(token, privatekey, async function(err, decoded) {
    if (err) {
      console.log("Error decoding token:", err);
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    console.log(decoded);
    
    if (decoded && (decoded.role === "owner" || decoded.role === "security")) {
      const data = req.body;
      
      res.send(
        registerVisitor(
          data.role,
          data.name,
          data.idNumber,
          data.documentType,
          data.gender,
          data.birthDate,
          data.age,
          data.documentExpiry,
          data.company,
          data.TelephoneNumber,
          data.vehicleNumber,
          data.category,
          data.ethnicity,
          data.photoAttributes,
          data.passNumber
        )
      );
    } else {
      console.log("You have no access to register a visitor!");
    }
  });
});



//change pass number
/**
 * @swagger
 * /changePassNumber:
 *   post:
 *     summary: Change pass number
 *     description: Change pass number for a user
 *     tags: [Owner, Security]
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
 *     tags: [Owner]
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

//CREATE(createListing for owner)
async function createListing1(client, newListing){
  const result = await client.db("assignmentCondo").collection("owner").insertOne(newListing);
  console.log(`New listing created with the following id: ${result.insertedId}`);
}

//CREATE(createListing for visitor)
async function createListing2(client, newListing){
  const result = await client.db("assignmentCondo").collection("visitor").insertOne(newListing);
  console.log(`New listing created with the following id: ${result.insertedId}`);
}

//READ(login as visitor)
async function loginVisitor(res, idNumber, password){
  await client.connect();
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: idNumber});
  if(exist){
    if(bcrypt.compare(password, await exist.password)){
      console.log("WELCOME!!");
      token = jwt.sign({idNumber: idNumber, privatekey});
      res.send("Token: "+ token);
    }
    else{
      console.log("Wrong password");
    }
  }
  else{
    console.log("Visitor is not exist/registered");
  }
}

//READ(view all visitors)
async function viewVisitor(idNumber, role){
  var exist;
  await client.connect();
  if(role == "owner" || role == "security"){
    exist = await client.db("assignmentCondo").collection("visitor").find({}).toArray();
  }
  else if(role == "visitor"){
    exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: idNumber});
  }
  return exist;
}

//READ(login as Owner)
async function loginOwner(res, idNumber, hashed){
  await client.connect()
  const result = await client.db("assignmentCondo").collection("owner").findOne({ idNumber: idNumber });
  const role = await result.role
  if (result) {
    //BCRYPT verify password
    bcrypt.compare(result.password, hashed, function(err, result){
      if(result == true){
        console.log("Access granted. Welcome");
        console.log("Password:", hashed);
        console.log("Role:", role);
        const token = jwt.sign({idNumber: idNumber, role: role}, privatekey);
        res.send("Token: ", token);
      }else{
        console.log("Wrong password");
      }
    });
  } 
  else {
      console.log("Owner not registered");
  }
}

//READ(login as Security)
async function loginSecurity(idNumber, hashed){
  await client.connect()
  const result = await client.db("assignmentCondo").collection("security").findOne({ idNumber: idNumber });
  const role = await result.role
  if (result) {
    //BCRYPT verify password
    bcrypt.compare(result.password, hashed, function(err, result){
      if(result == true){
        console.log("Access granted. Welcome")
        console.log("Password:", hashed)
        console.log("Role:", role)
        const token = jwt.sign({idNumber: idNumber, role: role}, privatekey);
        res.send("Token:", token);
      }else{
        console.log("Wrong password")
      }
    });
  }
  else {
      console.log("Security not registered")
  }
}

//CREATE(register Owner)
async function registerOwner(newrole, newname, newidNumber, newemail, newpassword, newphoneNumber){
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("owner").findOne({idNumber: newidNumber})
  if(exist){
    console.log("Owner has already registered")
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
    console.log("Owner registered sucessfully")
  }
}

//CREATE(register Visitor)
async function registerVisitor(newrole, newname, newidNumber, newdocumentType, newgender, newbirthDate, 
                        newage, newdocumentExpiry, newcompany, newTelephoneNumber, newvehicleNumber,
                        newcategory, newethnicity, newphotoAttributes, newpassNumber){
  //TODO: Check if username exist
  await client.connect()
  const exist = await client.db("assignmentCondo").collection("visitor").findOne({idNumber: newidNumber})
  hashed = await bcrypt.hash(password, 10);
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
          passNumber: newpassNumber 
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