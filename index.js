const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors')
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.4wc44xb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});
async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        const userCollection = client.db("PaySwift").collection("users");

        //middlewares
        const authenticateJWT = (req,res,next)=>{
            const authHeader = req.headers.authorization;
            if(authHeader){
                const token = authHeader.split(' ')[1];
                
                jwt.verify(token,process.env.JWT_SECRET,(err,user)=>{
                    if(err){
                        return res.sendStatus(403);
                    }
                    req.user = user;
                    next()
                })
            } else{
                req.sendStatus(401);
            }
        }

        //user register
        app.post('/register', async (req, res) => {
            const { name, pin, mobileNumber, email, role } = req.body;
            if (!name || !pin || !mobileNumber || !email) {
                return res.status(400).json({ error: 'All fields are required' });
            }
            if (pin.length !== 5 || isNaN(pin)) {
                return res.status(400).json({ error: 'PIN must be a 5 digit number' })
            }
            try {
                const existingUser = await userCollection.findOne({ $or: [{ mobileNumber }, { email }] })
                if (existingUser) {
                    return res.status(400).json({ error: 'User already exists' });
                }
                const hashedPin = await bcrypt.hash(pin, 10);
                const newUser = {
                    name,
                    pin: hashedPin,
                    mobileNumber,
                    email,
                    role: '',
                    status: 'pending',
                    balance: 0,
                };
                await userCollection.insertOne(newUser);
                res.status(201).json({ message: 'User registered successfully' });
            } catch (err) {
                res.status(500).json({ error: 'Internal server error' })
            }
        })

        //user login
        app.post('/login', async (req, res) => {
            const { identifier, pin } = req.body;
            if (!identifier || !pin) {
                return res.status(400).json({ error: 'Identifier and PIN are required' });
            }
            try {
                const user = await userCollection.findOne({
                    $or: [{ mobileNumber: identifier }, { email: identifier }]
                });
                if (!user) {
                    return res.status(401).json({ error: 'Invalid credentials' })
                }
                const isValidPin = await bcrypt.compare(pin, user.pin);
                if (!isValidPin) {
                    return res.status(401).json({ error: 'Invalid Credentials' })
                }
                if (user.status !== 'active') {
                    return res.status(403).json({ error: 'Account not activated' })
                }
                const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '2h' });
                res.status(200).json({ message: 'Login Successful', token });
            } catch (err) {
                res.status(500).json({ error: 'Internal server error' })
            }
        })

        //verify token endpoint
        app.get('/verifyToken',authenticateJWT,async(req,res)=>{
            try{
                const user = await userCollection.findOne({_id: req.user.id})
                if(!user){
                    return res.status(404).json({error:'User not found'})
                }
                res.status(200).json({user});
            } catch(err){
                res.status(500).json({error: 'Internal server error'});
            }
        });

        // Send a ping to confirm a successful connection
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('PaySwift is running')
})
app.listen(port, () => {
    console.log(`Server is running on port ${port}`)
});