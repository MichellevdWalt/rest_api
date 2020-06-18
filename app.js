'use strict';

// load modules
const express = require('express');
const morgan = require('morgan');
const bcryptjs = require('bcryptjs');
const auth = require('basic-auth');
const { Op } = require('sequelize');

// variable to enable global error logging
const enableGlobalErrorLogging = process.env.ENABLE_GLOBAL_ERROR_LOGGING === 'true';

//variables
const Course = require('./models').Course;
const User = require('./models').User;

// create the Express app
const app = express();
app.use(express.json());

// setup morgan which gives us http request logging
app.use(morgan('dev'));

//function to handle all async behaviour
function asyncHandler(cb){
  return async(req,res,next) => {
    try{
      await cb(req,res,next)
    } catch(error){
      res.status(500).send(error);
    }
  }
}

//authentication middleware
const authenticateUser = async (req, res, next) => {
  let message = null;
  const credentials = auth(req);
  console.log(credentials);
  if (credentials) {
    const user = await User.findOne({
      where:{
          emailAddress: {
              [Op.eq]: credentials.name
          }
      }
    });
    if (user) {
      const authenticated = bcryptjs
        .compareSync(credentials.pass, user.password);
      if (authenticated) {
        console.log(`Authentication successful for username: ${user.emailAddress}`);
        req.currentUser = user;
      } else {
        message = `Authentication failure for username: ${user.emailAddress}`;
      }
    } else {
      message = `User not found for username: ${credentials.name}`;
    }
  } else {
    message = 'Auth header not found';
  }

  if (message) {
    console.warn(message);
    res.status(401).json({ message: 'Access Denied' });
  } else {
    next();
  }
};

// Get route for user
app.get('/api/users', authenticateUser, asyncHandler(async(req,res) => {
  const currentUser = req.currentUser;
  const users = await User.findAll({
    where : {
      emailAddress: currentUser.emailAddress
    },
    attributes: ['id', 'firstName', 'lastName', 'emailAddress']
  });
  res.status(200).json(users)
}))

//Post route to post a new user
app.post('/api/users', asyncHandler(async (req,res) =>{
  let user;
  try{
    user = (req.body);
    user.password = bcryptjs.hashSync(user.password);
    const existing = await User.findOne({
      where: {
        emailAddress: {
          [Op.eq] : user.emailAddress
        }
      }
    })
    if(!existing){
    await User.create(user);
    res.status(201).location('/api/users/' + user.id).end()
    }else{
      res.status(400).json({"Error" : "Email address is already registered"})
    }
  } catch(error){
    if(error.name === "SequelizeValidationError") {
      console.log(req.body);
      res.status(400).json({"Error" : error.message})
    } else {
      throw error
    }
  }
}))

//returns a list of all courses
app.get('/api/courses', asyncHandler(async(req,res) =>{
    const courses = await Course.findAll({
      attributes: ["id", "userId", "title", "description", "estimatedTime", "materialsNeeded"],
      include: [{
        attributes: ["id", "firstName", "lastName", "emailAddress"],
        model:User
      }]
    });
    res.json(courses);
}))

//returns specific course by its ID
app.get('/api/courses/:id', asyncHandler(async(req,res) => {
  const course = await Course.findAll({
    where: {id: req.params.id}, 
    include: [{model: User}]
  });
  res.json(course);
}))

// POST /api/courses 201 - Creates a course, sets the Location header to the URI for the course, and returns no content
app.post('/api/courses', authenticateUser, asyncHandler(async(req,res)=>{
  let course;
  try{
    course = await Course.create(req.body);
    res.status(201).location('/api/courses/' + course.id).end()
  } catch(error){
    if(error.name === "SequelizeValidationError") {
      console.log(req.body);
      res.status(400).json({"Error" : error.message})
    } else {
      throw error
    }
  }
  
}))

// DELETE  - Deletes a user, if the user is the authenticated current user and authorized, and returns no content
app.delete('/api/users/:id', authenticateUser, asyncHandler(async(req,res) =>{
  let user = await User.findByPk(req.params.id);
  if(user){
    if(user.emailAddress === req.currentUser.emailAddress){
    await user.destroy();
    res.status(204).end()
    } else {
      res.status(203).json({"Error" : "You are not authorized to delete this user"})
    }
  } else {
    res.status(404).end();
  }
}))

// PUT /api/courses/:id 204 - Updates a course and returns no content
app.put('/api/courses/:id', authenticateUser, asyncHandler(async(req,res) =>{
  try{
  let course = await Course.findByPk(req.params.id)
  if(course){
    if(course.userId === req.currentUser.id){
    await course.update(req.body)
    res.status(204).end()
    }else{
      res.status(203).json({"Error" : "You are not authorized to edit this course"})
  }}
  }catch(error){
    if(error.name === "SequelizeValidationError") {
    res.json({"Error":error.message})
    } else {
      throw error
    }
  }
}))

// DELETE /api/courses/:id 204 - Deletes a course and returns no content
app.delete('/api/courses/:id', authenticateUser, asyncHandler(async(req,res) =>{ 
   let course = await Course.findByPk(req.params.id);
   console.log(course);
   if(course){
     if(course.userId === req.currentUser.id){
       await course.destroy();
       res.status(204).end()
     }else{
      res.status(203).json({"Error" : "You are not authorized to delete this course"})
     }
  } else {
    res.status(404).end();
  }
}))

// setup a friendly greeting for the root route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the REST API project!',
  });
});

// send 404 if no other route matched
app.use((req, res) => {
  res.status(404).json({
    message: 'Route Not Found',
  });
});

// setup a global error handler
app.use((err, req, res, next) => {
  if (enableGlobalErrorLogging) {
    console.error(`Global error handler: ${JSON.stringify(err.stack)}`);
  }

  res.status(err.status || 500).json({
    message: err.message,
    error: {},
  });
});

// set our port
app.set('port', process.env.PORT || 5000);

// start listening on our port
const server = app.listen(app.get('port'), () => {
  console.log(`Express server is listening on port ${server.address().port}`);
});
