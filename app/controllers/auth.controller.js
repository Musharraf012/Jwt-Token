const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = (req, res) => {
    const user = new User({
      username: req.body.username,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 8)
    });
  
    user.save()
      .then(user => {
        if (req.body.roles) {
          Role.find({ name: { $in: req.body.roles } })
            .then(roles => {
              user.roles = roles.map(role => role._id);
              return user.save();
            })
            .then(() => res.send({ message: "User was registered successfully!" }))
            .catch(err => res.status(500).send({ message: err }));
        } else {
          Role.findOne({ name: "user" })
            .then(role => {
              user.roles = [role._id];
              return user.save();
            })
            .then(() => res.send({ message: "User was registered successfully!" }))
            .catch(err => res.status(500).send({ message: err }));
        }
      })
      .catch(err => res.status(500).send({ message: err }));
  };
  
  exports.signin = (req, res) => {
    User.findOne({ username: req.body.username })
      .populate("roles", "-__v")
      .then((user) => {
        if (!user) {
          return res.status(404).send({ message: "User Not found." });
        }
  
        const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
  
        if (!passwordIsValid) {
          return res.status(401).send({
            accessToken: null,
            message: "Invalid Password!",
          });
        }
  
        const token = jwt.sign(
          { id: user.id },
          config.secret,
          {
            algorithm: "HS256",
            allowInsecureKeySizes: true,
            expiresIn: 86400, // 24 hours
          }
        );
  
        const authorities = user.roles.map(role => "ROLE_" + role.name.toUpperCase());
  
        res.status(200).send({
          id: user._id,
          username: user.username,
          email: user.email,
          roles: authorities,
          accessToken: token,
        });
      })
      .catch((err) => {
        res.status(500).send({ message: err.message || "Internal server error" });
      });
  };
  