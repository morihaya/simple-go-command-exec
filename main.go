package main

import (
	"time"

	"github.com/kataras/iris"
	"github.com/kataras/iris/middleware/basicauth"
	"github.com/kataras/iris/middleware/logger"
	"github.com/kataras/iris/middleware/recover"
)

func newApp() *iris.Application {
	app := iris.New()

	app.Logger().SetLevel("debug")
	// Optionally, add two built'n handlers
	// that can recover from any http-relative panics
	// and log the requests to the terminal.
	app.Use(recover.New())
	app.Use(logger.New())

	authConfig := basicauth.Config{
		Users:   map[string]string{"myusername": "mypassword", "mySecondusername": "mySecondpassword"},
		Realm:   "Authorization Required", // defaults to "Authorization Required"
		Expires: time.Duration(30) * time.Minute,
	}

	authentication := basicauth.New(authConfig)

	// to global app.Use(authentication) (or app.UseGlobal before the .Run)
	// to routes
	/*
		app.Get("/mysecret", authentication, h)
	*/

	//app.Get("/", func(ctx iris.Context) { ctx.Redirect("/admin") })

	// to party

	needAuth := app.Party("/admin", authentication)
	{
		//http://localhost:8080/admin
		needAuth.Get("/", h)
		// http://localhost:8080/admin/profile
		needAuth.Get("/profile", h)

		// http://localhost:8080/admin/settings
		needAuth.Get("/settings", h)
	}

	// Method:   GET
	// Resource: http://localhost:8080
	app.Handle("GET", "/", func(ctx iris.Context) {
		ctx.HTML("<h1>Welcome</h1>")
	})

	// same as app.Handle("GET", "/ping", [...])
	// Method:   GET
	// Resource: http://localhost:8080/ping
	app.Get("/ping", func(ctx iris.Context) {
		ctx.WriteString("pong")
	})

	// Method:   GET
	// Resource: http://localhost:8080/hello
	app.Get("/hello", func(ctx iris.Context) {
		ctx.JSON(iris.Map{"message": "Hello Iris!"})
	})

	return app
}

func main() {
	app := newApp()
	// open http://localhost:8080/admin
	app.Run(iris.Addr(":8080"))
}

func h(ctx iris.Context) {
	username, password, _ := ctx.Request().BasicAuth()
	// third parameter it will be always true because the middleware
	// makes sure for that, otherwise this handler will not be executed.

	ctx.Writef("%s %s:%s", ctx.Path(), username, password)
}
