const express = require('express');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const serverless = require('serverless-http');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid'); // Import uuid library

const app = express();
const port = 3000; // You can choose any port you want

// Initialize AWS SDK
const ses = new AWS.SES({ region: 'us-east-1' });
const dynamoDB = new AWS.DynamoDB.DocumentClient();

const TABLE_NAME = 'tempTokenExpress';

// Middleware to parse JSON requests
app.use(express.json());

// Route for handling forgot password requests
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    console.log('Email:', email);

    // Generate a random token using uuid and set expiration time to 15 minutes from now
    const token = uuidv4();
    const expirationTime = new Date();
    expirationTime.setMinutes(expirationTime.getMinutes() + 15); // Token expires in 15 minutes

    // Store the token and expiration time in DynamoDB against the user's email
    await dynamoDB.put({
      TableName: TABLE_NAME,
      Item: {
        email,
        token,
        expiresAt: expirationTime.getTime(), // Store expiration time in milliseconds
      },
    }).promise();

    // Send email with the token
    await ses.sendEmail({
      Source: 'kj.me.cd@gmail.com',
      Destination: {
        ToAddresses: [email],
      },
      Message: {
        Subject: {
          Data: 'Password Reset Request',
        },
        Body: {
          Text: {
            Data: `Your password reset token is: ${token}`,
          },
        },
      },
    }).promise();

    // Return success response
    res.status(200).json({ message: 'Password reset token sent successfully via email' });
  } catch (error) {
    console.error('Error:', error);
    // Return error response
    res.status(500).json({ message: 'Error processing forgot password request' });
  }
});


// Route for comparing the token
app.post('/compare-token', async (req, res) => {
  try {
    const { email, token } = req.body;
    // Retrieve the token and expiration time from DynamoDB based on the user's email
    const data = await dynamoDB.get({
      TableName: TABLE_NAME,
      Key: { email }
    }).promise();

    if (!data.Item) {
      return res.status(400).json({ message: 'Invalid email or token' });
    }

    const { token: storedToken, expiresAt } = data.Item;

    // Check if the provided token matches the stored token
    if (token !== storedToken) {
      return res.status(400).json({ message: 'Invalid email or token' });
    }

    // Check if the token is expired
    if (Date.now() > expiresAt) {
      return res.status(400).json({ message: 'Token has expired' });
    }

    // Return success response
    return res.status(200).json({ message: 'Token is valid' });
  } catch (error) {
    console.error('Error:', error);
    // Return error response
    return res.status(500).json({ message: 'Error comparing token' });
  }
});

// Route for resetting the password
app.post('/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    // Retrieve the token and expiration time from DynamoDB based on the user's email
    const data = await dynamoDB.get({
      TableName: TABLE_NAME,
      Key: { email }
    }).promise();

    if (!data.Item) {
      return res.status(400).json({ message: 'Invalid email or token' });
    }

    const { token: storedToken, expiresAt } = data.Item;

    // Check if the provided token matches the stored token
    if (token !== storedToken) {
      return res.status(400).json({ message: 'Invalid email or token' });
    }

    // Check if the token is expired
    if (Date.now() > expiresAt) {
      return res.status(400).json({ message: 'Token has expired' });
    }

    // Hash the new Password

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database

    await dynamoDB.update({ 
      TableName: TABLE_NAME,
      Key: { email },
      UpdateExpression: 'set password = :p',
      ExpressionAttributeValues: {
        ':p': hashedPassword
      }
    }).promise();

    // Return success response
    return res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Error:', error);
    // Return error response
    return res.status(500).json({ message: 'Error resetting password' });
  }
});


// Start the Express server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// Export the Express app wrapped with serverless
module.exports.handler = serverless(app);
