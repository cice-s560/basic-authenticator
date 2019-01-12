var express = require('express');
var router = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const UserModel = require("../models/User");

function checkToken(req, res, next) {
    if (!req.headers.authorization) {
        return res.status(401).send();
    }

    const token = req.headers.authorization.toString().split("Bearer ")[1];

    jwt.verify(token, process.env.SECRET_JWT, (err, payload) => {
        if (err) {
            return res.status(401).send();
        }

        req.userId = payload.user;

        next();
    });
}

router.post('/', async function(req, res, next) {
  if (!req.body.username.toString().trim()) { return res.status(400).send(); }
  if (!req.body.password.toString().trim()) { return res.status(400).send(); }

  const user = await UserModel.findOne({username: req.body.username});

  if (!user) {
    return res.status(400).send("Usuario no existe");
  }

  bcrypt.compare(req.body.password.toString(), user.password, function(err, result) {
        if (err) {
            res.status(400).send("Password erróneo"); // mala práctica. Mejor no decir porqué en producción
            throw err;
        }

        if (!result) {
            return res.status(400).send("Password erróneo"); // mala práctica. Mejor no decir porqué en producción
        }

        // Si result es TRUE debería generar un JWT
        jwt.sign({user: user._id}, process.env.SECRET_JWT, (err, token) => {
            if (err) {
                throw err;
            }

            res.status(200).json({token});
        });
    });
});

router.post('/create', async function(req, res, next) {
    const user = new UserModel({
        username: req.body.username
    });

    bcrypt.hash(req.body.password.toString(), 10, async function(err, hash) {
        if (err) {
            throw err;
        }

        user.password = hash;

        await user.save().catch(err => {
            throw err;
            return res.status(500).send()
        });

        return res.status(201).send();
      });
  });


router.get("/check", checkToken, (req, res) => {
    return res.render("private-page", {userId: req.userId});
});

module.exports = router;
