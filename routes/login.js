var express = require('express');
var router = express.Router();
const bcrypt = require("bcrypt");
const UserModel = require("../models/User");

function checkSession(req, res, next) {
    if (req.session && req.session.user) {
        next();
    }

    return res.status(401).send();
}

router.post('/', async function(req, res, next) {
  if (!req.body.username.toString().trim()) { return res.status(400).send(); }
  if (!req.body.password.toString().trim()) { return res.status(400).send(); }

  const user = await UserModel.findOne({username: req.body.username});

  bcrypt.compare(req.body.password.toString(), user.password, function(err, result) {
        if (err) {
            throw err;
        }

        // Si result es TRUE debería crear una session
        if (result) {
            req.session.user = user._id;
        }

        res.status(200).send(result);
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


router.get("/check", checkSession, (req, res) => {
    return res.render("private-page", {userId: req.session.user});
});

module.exports = router;
