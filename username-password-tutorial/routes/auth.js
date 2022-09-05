var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local');
var crypto = require('crypto');
var db = require('../db');

passport.use( new LocalStrategy( function( username, password, cb) {
    db.get('SELECT rowid AS id, * FROM users WHERE username = ?', [username], ( error, row ) => {
        if( error ) return cb( error );
        if( !row ) { return cb( null, false, { message: 'Incorrect username or password.' }) }

        crypto.pbkdf2( password, row.salt, 310000, 32, 'sha256', ( error, hashedPassword ) => {
            if( error ) return cb( error );
            if( !crypto.timingSafeEqual( row.hashed_password, hashedPassword ) ) {
                return cb( null, false, { message: 'Incorrect username or password' })
            }
        })
        return cb( null, row )
    }
    )
    
}));

passport.serializeUser(( user, cb ) => {
    cb( null, {
        id: user.id,
        username: user.username
    })
});
passport.deserializeUser(( user, cb ) => {
    process.nextTick( function() { return cb( null, user ) } )
})

router.get('/login', ( req, res, next ) => {
    res.render('login')
});

router.post('/login/password', passport.authenticate('local', {
    successRedirect:'/',
    failureRedirect:'/login'
}));

router.post('/logout', ( req, res, next ) => {
    req.logout();
    res.redirect('/');
})

router.get('/signup', ( req, res, next ) => {
    res.render('signup')
})

router.post('/signup', function( req, res, next ) {
    var salt = crypto.randomBytes(16);
    crypto.pbkdf2( req.body.password, salt, 310000, 32, 'sha256', function( error, hashedPassword ) {
        if( error ) return next( error );
        db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
            req.body.username,
            hashedPassword,
            salt
        ], function( error ) {
            if( error ) return next( error );
            var user = {
                id: this.lastID,
                username: req.body.username
            }
            req.login( user, function( error ) {
                if( error ) return next( error );
                res.redirect('/')
            });
        });
    });
});

module.exports = router;