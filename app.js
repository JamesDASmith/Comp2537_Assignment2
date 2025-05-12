const express =     require('express');
const session =     require('express-session');
const MongoStore =  require('connect-mongo');
const bcrypt =      require('bcrypt');

require('dotenv').config();
const Joi = require('joi');
const { MongoClient } = require('mongodb');


const app = express();                  // Create an instance of express
const port = process.env.PORT || 3000;  // Set the view engine to ejs

const saltRounds = 12;                  // Number of rounds for bcrypt hashing
const expireTime = 1000 * 60 * 60       // 1 hour
const node_session_secret = process.env.NODE_SESSION_SECRET; // Use environment variable for session secret

const mongodb_user =        process.env.MONGODB_USER; // Use environment variable for username
const mongodb_password =    process.env.MONGODB_PASSWORD; // Use environment variable for password
const uri =                 `mongodb+srv://${mongodb_user}:${mongodb_password}@${process.env.MONGODB_HOST}/`;
const client =              new MongoClient(uri);

const loginSchema = Joi.object({
                        email: Joi.string().email().required(),
                        password: Joi.string().min(1).required()
  });

  let usersCollection;


// --MIDDLEWARE--
// Middleware to parse JSON bodies
app.use(express.urlencoded({extended: false}));

app.use(express.static('public'));

app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
        return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
});

app.set('trust proxy', 1);
app.set('view engine', 'ejs'); // Set the view engine to ejs


// Create a new MongoDB store instance
var mongoStore = MongoStore.create({ 
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
})

// Middleware to serve static files from the 'public' directory
app.use(session({
    secret:             node_session_secret,
    store:              mongoStore,
    saveUninitialized:  false,
    resave:             true,
    cookie: {
        maxAge: expireTime,
        sameSite: 'lax',
        secure:  true // false <- for local testing, true <- for production
    }
}));


async function connectToMongo() 
{
  try 
  {
    await client.connect();
    const db = client.db(`${process.env.MONGODB_DATABASE}`); 
    usersCollection = db.collection("users"); // store users here
    console.log("Connected to MongoDB Atlas");
  } 
  catch (err) 
  {
    console.error("MongoDB connection error:", err);
  }
}

connectToMongo();

function isValidSession(req)
{
    if (req.session.authenticated)
    {
        return true;
    }
    else
    {
        return false;
    }
}

function sessionValidation(req, res, next)
{
    if (isValidSession(req))
    {
        next();
    }
    else
    {
        res.redirect('/login');
    }
}

function isAdmin(req, res, next)
{
    if (req.session.userType === 'admin')
    {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) 
{
    if(isAdmin(req))
    {
        next();
    }
    else
    {
        var errorType = 403;
        var errorMessage = "Forbidden: You do not have permission to access this page.";

        res.status(errorType);
        res.render('error.ejs', { authenticated: false,  
                                    errorType: errorType,
                                    errorMessage: errorMessage,
                                    currentPage: 'error' });
    }
}



// -- ROUTES --
// Home Page
app.get('/', (req, res) =>
{
    if(isValidSession(req))
    {
        res.render('home.ejs', { authenticated: true, 
                                 username: req.session.username,
                                 currentPage: 'home' });  
    }
    else
    {
        res.render('entry.ejs', { authenticated: false });
    }

});

// Sign Up Page
app.get('/signup', (req, res) =>
{
    res.render('signup.ejs', { authenticated: false, 
                               missingFields: req.query.missingFields });

});

// Login Page
app.get('/login', (req, res) =>
{
    res.render('login.ejs', { authenticated: false });
});

// Members Page
app.use('/members', sessionValidation);
app.get('/members', (req, res) =>
{
    res.render('members.ejs', { authenticated: true, 
                                username: req.session.username,
                                currentPage: 'members' });
});

// Admin Page
app.use('/admin', sessionValidation);
app.use('/admin', adminAuthorization);
app.get('/admin', async (req, res) =>
{
    try 
    {
        const users = await usersCollection.find({}).toArray();

        res.render('admin.ejs', { authenticated: true, 
                                    username: req.session.username,
                                    users: users,
                                    currentPage: 'admin' });
    }
    catch (err) 
    {
        console.error("Error fetching users:", err);
        res.status(500).send("Error loading admin page.");
    }
    
})

// Create User
app.post('/createUser', async (req, res) =>
{
    var username =  req.body.username;
    var email =     req.body.email;
    var password =  req.body.password;
    var userType =  'user';

    // Check if any of the fields are empty, if so redirect to signup page with a query parameter
    if(!email || !password || !username)
    {
        res.redirect('/signup?missingFields=1');
        return;
    }

    var hashedPassword = bcrypt.hashSync(password, saltRounds); // Hash the password

    try {
        await usersCollection.insertOne({ username, email, password: hashedPassword, userType });
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/');
      } catch (err) {
        console.error("Error saving user:", err);
        res.send("Error creating user.");
      }

});

// Login User
app.post('/loginUser', async (req, res) =>
{
    var email =     req.body.email;
    var password =  req.body.password;

    const { error } = loginSchema.validate({ email, password});
    if (error) {
        console.error("Validation error:", error.details);
        return res.status(400).send('Invalid Password');
      }

    const user = await usersCollection.findOne({ email });

  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.authenticated =     true;
    req.session.email =             email;
    req.session.username =          user.username;
    req.session.cookie.maxAge =     expireTime;
    req.session.userType =          user.userType;
    return res.redirect('/');
  }

  res.redirect('/login');
});

// Logout Page
app.get('/logout', (req, res) =>
{
    req.session.destroy(err => 
        {
        if (err) 
            {
            console.error("Error destroying session:", err);
            return res.send("Error logging out.");
        }

        // Clear session cookie
        res.clearCookie('connect.sid');

        // Redirect to home page or login
        res.redirect('/');
    });
});  

app.post('/admin/promote', adminAuthorization, async (req, res) =>
{
    const email = req.body.email;

    try 
    {
        await usersCollection.updateOne({ email},
                                       { $set: { userType: 'admin' }});
        res.redirect('/admin'); 
    } 
    catch (err) 
    {
        console.error("Error promoting user:", err);
        res.status(500).send("Error promoting user.");
    }

});

app.post('/admin/demote', adminAuthorization, async (req, res) =>
{
    const email = req.body.email;
    if (req.body.email === req.session.email)
    {
        return res.send("You cannot demote yourself.");
    }

    try 
    {
        await usersCollection.updateOne({ email},
                                        { $set: { userType: 'user' }});
        res.redirect('/admin');
    }
    catch (err)
    {
        console.error("Error demoting user:", err);
        res.status(500).send("Error demoting user.");
    }
});


// 404 Page Not Found
app.get('*', (req, res) =>
{
    var errorType = 404;
    var errorMessage = "Page Not Found";

    res.status(errorType);
    res.render('error.ejs', { authenticated: false,  
                              errorType: errorType,
                              errorMessage: errorMessage,
                              currentPage: 'error' });
});

// --SERVER--
// Start the Server
app.listen(port, () => 
{
    console.log(`Server is running on http://localhost: ${port}`);
});
