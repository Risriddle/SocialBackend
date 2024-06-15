const secrets = require('crypto');


const axios = require('axios');
const config = require('config');

const GMAIL_ADDRESS = config.get('GMAIL_ADDRESS');
const GMAIL_NAME = config.get('GMAIL_NAME');
const BREVO_API = config.get('BREVO_API');


function generateOtp() {
    return Array.from({ length: 6 }, () => Math.floor(Math.random() * 10)).join('');
}



function sendMail(address, generatedOtp) {
    const url = "https://api.brevo.com/v3/smtp/email";
    const headers = {
        "accept": "application/json",
        "api-key": BREVO_API,
        "content-type": "application/json"
    };
    const payload = {
        "sender": {
            "name": GMAIL_NAME,
            "email": GMAIL_ADDRESS
        },
        "to": [
            {
                "email": address,
            }
        ],
        "subject": "OTP Verification",
        "htmlContent": `<!DOCTYPE html>
                        <html>
                        <head>
                            <title>OTP Verification</title>
                        </head>
                        <body>
                            <h3>OTP Verification</h3>
                            <p>Hello USER,</p>
                            <p>Your One-Time Password (OTP) for verification is: <strong>${generatedOtp}</strong></p>
                            <p>Please use this OTP to complete your verification process. This OTP will expire in 30 minutes.</p>
                            <p>If you did not request this OTP, please ignore this email.</p>
                            <p>Thank you for using our service!</p>
                            <p>Best regards,<br>MST Organization</p>
                        </body>
                        </html>`
    };

    return axios.post(url, payload, { headers })
        .then(response => {
            if (response.status === 200 || response.status === 201) {
                console.log(`OTP sent successfully to ${address}`);
                return true;
            } else {
                console.log(`Failed to send OTP! Status code: ${response.status}`);
                console.log(response.data);
                return false;
            }
        })
        .catch(error => {
            console.error('Error sending OTP:', error);
            return false;
        });
}



module.exports={
    generateOtp,
    sendMail
}