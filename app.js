// importing required module
const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt"); // for making the password encrypted before saving as plain text in database

const databasePath = path.join(__dirname, "userData.db");

const app = express();

app.use(express.json());

let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });

    app.listen(3000, () =>
      console.log("Server Running at http://localhost:3000/")
    );
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

// validating the length of password
const validatePassword = (password) => {
  return password.length > 4;
};

// register API
app.post("/register", async (request, response) => {
  // extracting all info from request body
  const { username, name, password, gender, location } = request.body;
  // making the password hashed(encrypted) for saving this in database
  const hashedPassword = await bcrypt.hash(password, 10);
  // Query to check the user who want to register, are already in database or not
  const selectUserQuery = `SELECT * FROM user WHERE username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);

  if (databaseUser === undefined) {
    // databaseUser === undefined mean user are new and it's not in database
    // Query for inserting this new user in database
    const createUserQuery = `
     INSERT INTO
      user (username, name, password, gender, location)
     VALUES
      (
       '${username}',
       '${name}',
       '${hashedPassword}',
       '${gender}',
       '${location}'  
      );`;
    // now checking password length
    if (validatePassword(password)) {
      // for validatePassword(password) is true we are performing query on database to insert the user and send successfull response
      await database.run(createUserQuery);
      response.send("User created successfully");
    } else {
      // if validatePassword(password) is false we are sending error with proper message
      response.status(400);
      response.send("Password is too short");
    }
  } else {
    //databaseUser === undefined is false mean user already exist in database
    response.status(400);
    response.send("User already exists");
  }
});

//Login API
app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  // Query to check the username validated from database or not
  const selectUserQuery = `SELECT * FROM user WHERE username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);

  // if databaseUser === undefined mean the user tried to login doesn't exist in database
  if (databaseUser === undefined) {
    response.status(400);
    response.send("Invalid user");
  } else {
    // now matching the password with hashed password saved in database  by bcrypt compare method & if it matched send response as successfull login
    const isPasswordMatched = await bcrypt.compare(
      password,
      databaseUser.password
    );
    if (isPasswordMatched === true) {
      response.send("Login success!");
    } else {
      response.status(400);
      response.send("Invalid password");
    }
  }
});

// Changing password API
app.put("/change-password", async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;
  // Query to check the username validated from database or not
  const selectUserQuery = `SELECT * FROM user WHERE username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);
  if (databaseUser === undefined) {
    //if databaseUser === undefined mean the user tried to login doesn't exist in database
    response.status(400);
    response.send("Invalid user");
  } else {
    // now matching the password with hashed password saved in database
    const isPasswordMatched = await bcrypt.compare(
      oldPassword,
      databaseUser.password
    );
    // if isPasswordMatched === true then update the old password with new one
    if (isPasswordMatched === true) {
      // here validating the password length
      if (validatePassword(newPassword)) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updatePasswordQuery = `
          UPDATE
            user
          SET
            password = '${hashedPassword}'
          WHERE
            username = '${username}';`;

        const user = await database.run(updatePasswordQuery);

        response.send("Password updated");
      } else {
        response.status(400);
        response.send("Password is too short");
      }
    } else {
      response.status(400);
      response.send("Invalid current password");
    }
  }
});

// exporting app
module.exports = app;
