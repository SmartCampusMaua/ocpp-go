# ocpp-go

[![Build Status](https://github.com/lorenzodonini/ocpp-go/actions/workflows/test.yaml/badge.svg)](https://github.com/lorenzodonini/ocpp-go/actions/workflows/test.yaml)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4)](https://godoc.org/github.com/lorenzodonini/ocpp-go)
[![Coverage Status](https://coveralls.io/repos/github/lorenzodonini/ocpp-go/badge.svg?branch=master)](https://coveralls.io/github/lorenzodonini/ocpp-go?branch=master)
[![Go report](https://goreportcard.com/badge/github.com/lorenzodonini/ocpp-go)](https://goreportcard.com/report/github.com/lorenzodonini/ocpp-go)

Open Charge Point Protocol implementation in Go.

The library targets modern charge points and central systems, running OCPP version 1.6+.

Given that SOAP will no longer be supported in future versions of OCPP, only OCPP-J is supported in this library.
There are currently no plans of supporting OCPP-S.

## Status & Roadmap

**Note: Releases 0.10.0 introduced breaking changes in some API, due to refactoring. The functionality remains the same,
but naming changed.**

Planned milestones and features:

-   [x] OCPP 1.6
-   [x] OCPP 1.6 Security extension (experimental)
-   [x] OCPP 2.0.1 (examples working, but will need more real-world testing)
-   [ ] Dedicated package for configuration management

## OCPP 1.6 Usage

Go version 1.13+ is required.

```sh
go get github.com/lorenzodonini/ocpp-go
```

You will also need to fetch some dependencies:

```sh
cd <path-to-ocpp-go>
export GO111MODULE=on
go mod download
```

Your application may either act as a [Central System](#central-system) (server) or as a [Charge Point](#charge-point) (
client).

### Central System

If you want to integrate the library into your custom Central System, you must implement the callbacks defined in the
profile interfaces, e.g.:

```go
import (
"github.com/lorenzodonini/ocpp-go/ocpp1.6/core"
"github.com/lorenzodonini/ocpp-go/ocpp1.6/types"
"time"
)

const defaultHeartbeatInterval = 600

type CentralSystemHandler struct {
// ... your own state variables
}

func (handler *CentralSystemHandler) OnAuthorize(chargePointId string, request *core.AuthorizeRequest) (confirmation *core.AuthorizeConfirmation, err error) {
// ... your own custom logic
return core.NewAuthorizationConfirmation(types.NewIdTagInfo(types.AuthorizationStatusAccepted)), nil
}

func (handler *CentralSystemHandler) OnBootNotification(chargePointId string, request *core.BootNotificationRequest) (confirmation *core.BootNotificationConfirmation, err error) {
// ... your own custom logic
return core.NewBootNotificationConfirmation(types.NewDateTime(time.Now()), defaultHeartbeatInterval, core.RegistrationStatusAccepted), nil
}

// further callbacks...
```

Every time a request from the charge point comes in, the respective callback function is called.
For every callback you must return either a confirmation or an error. The result will be sent back automatically to the
charge point.
The callback is invoked inside a dedicated goroutine, so you don't have to worry about synchronization.

You need to implement at least all other callbacks defined in the `core.CentralSystemHandler` interface.

Depending on which OCPP profiles you want to support in your application, you will need to implement additional
callbacks as well.

To start a central system instance, simply run the following:

```go
centralSystem := ocpp16.NewCentralSystem(nil, nil)

// Set callback handlers for connect/disconnect
centralSystem.SetNewChargePointHandler(func (chargePointId string) {
log.Printf("new charge point %v connected", chargePointId)
})
centralSystem.SetChargePointDisconnectedHandler(func (chargePointId string) {
log.Printf("charge point %v disconnected", chargePointId)
})

// Set handler for profile callbacks
handler := &CentralSystemHandler{}
centralSystem.SetCoreHandler(handler)

// Start central system
listenPort := 8887
log.Printf("starting central system")
centralSystem.Start(listenPort, "/{ws}") // This call starts server in daemon mode and is blocking
log.Println("stopped central system")
```

#### Sending requests

To send requests to the charge point, you may either use the simplified API:

```go
err := centralSystem.ChangeAvailability("1234", myCallback, 1, core.AvailabilityTypeInoperative)
if err != nil {
log.Printf("error sending message: %v", err)
}
```

or create a message manually:

```go
request := core.NewChangeAvailabilityRequest(1, core.AvailabilityTypeInoperative)
err := centralSystem.SendRequestAsync("clientId", request, callbackFunction)
if err != nil {
log.Printf("error sending message: %v", err)
}
```

In both cases, the request is sent asynchronously and the function returns right away.
You need to write the callback function to check for errors and handle the confirmation on your own:

```go
myCallback := func (confirmation *core.ChangeAvailabilityConfirmation, e error) {
if e != nil {
log.Printf("operation failed: %v", e)
} else {
log.Printf("status: %v", confirmation.Status)
// ... your own custom logic
}
}
```

Since the initial `centralSystem.Start` call blocks forever, you may want to wrap it in a goroutine (that is, if you
need to run other operations on the main thread).

#### Example

You can take a look at the [full example](./example/1.6/cs/central_system_sim.go).
To run it, simply execute:

```bash
go run ./example/1.6/cs/*.go
```

#### Docker

A containerized version of the central system example is available:

```bash
docker pull ldonini/ocpp1.6-central-system:latest
docker run -it -p 8887:8887 --rm --name central-system ldonini/ocpp1.6-central-system:latest
```

You can also run it directly using docker-compose:

```sh
docker-compose -f example/1.6/docker-compose.yml up central-system
```

#### TLS

If you wish to test the central system using TLS, make sure you put your self-signed certificates inside the
`example/1.6/certs` folder.

Feel free to use the utility script `cd example/1.6 && ./create-test-certificates.sh` for generating test certificates.

Then run the following:

```
docker-compose -f example/1.6/docker-compose.tls.yml up central-system
```

### Charge Point

If you want to integrate the library into your custom Charge Point, you must implement the callbacks defined in the
profile interfaces, e.g.:

```go
import (
"github.com/lorenzodonini/ocpp-go/ocpp1.6/core"
"github.com/lorenzodonini/ocpp-go/ocpp1.6/types"
)

type ChargePointHandler struct {
// ... your own state variables
}

func (handler *ChargePointHandler) OnChangeAvailability(request *core.ChangeAvailabilityRequest) (confirmation *core.ChangeAvailabilityConfirmation, err error) {
// ... your own custom logic
return core.NewChangeAvailabilityConfirmation(core.AvailabilityStatusAccepted), nil
}

func (handler *ChargePointHandler) OnChangeConfiguration(request *core.ChangeConfigurationRequest) (confirmation *core.ChangeConfigurationConfirmation, err error) {
// ... your own custom logic
return core.NewChangeConfigurationConfirmation(core.ConfigurationStatusAccepted), nil
}

// further callbacks...
```

When a request from the central system comes in, the respective callback function gets invoked.
For every callback you must return either a confirmation or an error. The result will be sent back automatically to the
central system.

You need to implement at least all other callbacks defined in the `core.ChargePointHandler` interface.

Depending on which OCPP profiles you want to support in your application, you will need to implement additional
callbacks as well.

To start a charge point instance, simply run the following:

```go
chargePointId := "cp0001"
csUrl = "ws://localhost:8887"
chargePoint := ocpp16.NewChargePoint(chargePointId, nil, nil)

// Set a handler for all callback functions
handler := &ChargePointHandler{}
chargePoint.SetCoreHandler(handler)

// Connects to central system
err := chargePoint.Start(csUrl)
if err != nil {
log.Println(err)
} else {
log.Printf("connected to central system at %v", csUrl)
mainRoutine() // ... your program logic goes here
}

// Disconnect
chargePoint.Stop()
log.Printf("disconnected from central system")
```

#### Sending requests

To send requests to the central station, you have two options. You may either use the simplified synchronous blocking
API (recommended):

```go
bootConf, err := chargePoint.BootNotification("model1", "vendor1")
if err != nil {
log.Fatal(err)
} else {
log.Printf("status: %v, interval: %v, current time: %v", bootConf.Status, bootConf.Interval, bootConf.CurrentTime.String())
}
// ... do something with the confirmation
```

or create a message manually:

```go
request := core.NewBootNotificationRequest("model1", "vendor1")
```

You can then decide to send the message using a synchronous blocking call:

```go
// Synchronous call
confirmation, err := chargePoint.SendRequest(request)
if err != nil {
log.Printf("error sending message: %v", err)
}
bootConf := confirmation.(*core.BootNotificationConfirmation)
// ... do something with the confirmation
```

or an asynchronous call:

```go
// Asynchronous call
err := chargePoint.SendRequestAsync(request, callbackFunction)
if err != nil {
log.Printf("error sending message: %v", err)
}
```

In the latter case, you need to write the callback function and check for errors on your own:

```go
callback := func (confirmation ocpp.Response, e error) {
bootConf := confirmation.(*core.BootNotificationConfirmation)
if e != nil {
log.Printf("operation failed: %v", e)
} else {
log.Printf("status: %v", bootConf.Status)
// ... your own custom logic
}
}
```

When creating a message manually, you always need to perform type assertion yourself, as the `SendRequest` and
`SendRequestAsync` APIs use generic `Request` and `Confirmation` interfaces.

#### Example

You can take a look at the [full example](./example/1.6/cp/charge_point_sim.go).
To run it, simply execute:

```bash
CLIENT_ID=chargePointSim CENTRAL_SYSTEM_URL=ws://<host>:8887 go run example/1.6/cp/*.go
```

You need to specify the URL of a running central station server via environment variable, so the charge point can reach
it.

#### Docker

A containerized version of the charge point example is available:

```bash
docker pull ldonini/ocpp1.6-charge-point:latest
docker run -e CLIENT_ID=chargePointSim -e CENTRAL_SYSTEM_URL=ws://<host>:8887 -it --rm --name charge-point ldonini/ocpp1.6-charge-point:latest
```

You need to specify the host, on which the central system is running, in order for the charge point to connect to it.

You can also run it directly using docker-compose:

```sh
docker-compose -f example/1.6/docker-compose.yml up charge-point
```

#### TLS

If you wish to test the charge point using TLS, make sure you put your self-signed certificates inside the
`example/1.6/certs` folder.

Feel free to use the utility script `cd example/1.6 && ./create-test-certificates.sh` for generating test certificates.

Then run the following:

```
docker-compose -f example/1.6/docker-compose.tls.yml up charge-point
```

## OCPP 1.6 Security extension

The library supports the OCPP 1.6 Security extension, which adds support for additional messages that aren't a part of
original OCPP 1.6 specification. The security extension is optional, but recommended to implement.

There aren't any clear examples how to determine if a charge point supports security extensions via `SupportedProfiles`
configuration key or which profiles are required to be implemented in order to support the security extension.
As of now, the security extension is split into multiple profiles/functional blocks:

- `ExtendedTriggerMessage`
- `Certificates` (certificate management)
- `Security` (event notifications, certificate signing)
- `SecureFirmware` (secure firmware update)
- `Logging`

### HTTP Basic Auth

The security extension specifies how to secure the communication between charge points and central systems
using HTTP Basic Auth and/or certificates. These are already provided in the websocket server/client
implementation.

Example charge point:

```go
wsClient := ws.NewClient()
wsClient.SetBasicAuth("foo", "bar")
cp := ocpp16.NewChargePoint(chargePointID, nil, wsClient)
```

Example central system:

```go
server := ws.NewServer()
server.SetBasicAuthHandler(func (username string, password string) bool {
// todo Handle basic auth
return true
})
cs := ocpp16.NewCentralSystem(nil, server)
```

### Certificate-based authentication (mTLS)

The security extension specifies how to secure the communication between charge points and central systems
using mTLS (client certificates). The library provides the necessary functionality to configure TLS,
but mTLS itself is not in scope and should be handled by the user.

### Additional configuration keys

The OCPP 1.6 security extension introduces additional configuration keys.
These are not a part of the standard library, but they impact how the charge point should behave.

The charge point websocket client should be restarted when the `AuthorizationKey` configuration changes.

### Central System

To add support for security extension in the central system, you have the following handlers:

```go
// Support callbacks for all OCPP 1.6 profiles
handler := &CentralSystemHandler{chargePoints: map[string]*ChargePointState{}}
centralSystem.SetCoreHandler(handler)
centralSystem.SetLocalAuthListHandler(handler)
centralSystem.SetFirmwareManagementHandler(handler)
centralSystem.SetReservationHandler(handler)
centralSystem.SetRemoteTriggerHandler(handler)
centralSystem.SetSmartChargingHandler(handler)

// Add callbacks for OCPP 1.6 security profiles
centralSystem.SetSecurityHandler(handler)
centralSystem.SetSecureFirmwareHandler(handler)
centralSystem.SetLogHandler(handler)

```

### Charge Point

To add support for security extension in the charge point, you have the following handlers:

```go
handler := &ChargePointHandler{}
// Support callbacks for all OCPP 1.6 profiles
chargePoint.SetCoreHandler(handler)
chargePoint.SetFirmwareManagementHandler(handler)
chargePoint.SetLocalAuthListHandler(handler)
chargePoint.SetReservationHandler(handler)
chargePoint.SetRemoteTriggerHandler(handler)
chargePoint.SetSmartChargingHandler(handler)
// OCPP 1.6j Security extension
chargePoint.SetCertificateHandler(handler)
chargePoint.SetLogHandler(handler)
chargePoint.SetSecureFirmwareHandler(handler)
chargePoint.SetExtendedTriggerMessageHandler(handler)
chargePoint.SetSecurityHandler(handler)

```

## Advanced Features

The library offers several advanced features, especially at websocket and ocpp-j level.

### Automatic message validation

All incoming and outgoing messages are validated by default, using the [validator](gopkg.in/go-playground/validator)
package.
Constraints are defined on every request/response struct, as per OCPP specs.

Validation may be disabled at a package level if needed:

```go
ocppj.SetMessageValidation(false)
```

Use at your own risk, as this will disable validation for all messages!

> I will be evaluating the possibility to selectively disable validation for a specific message,
> e.g. by passing message options.

### Verbose logging

The `ws` and `ocppj` packages offer the possibility to enable verbose logs, via your logger of choice, e.g.:

```go
// Setup your own logger
log = logrus.New()
log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
log.SetLevel(logrus.DebugLevel) // Debug level needed to see all logs
// Pass own logger to ws and ocppj packages
ws.SetLogger(log.WithField("logger", "websocket"))
ocppj.SetLogger(log.WithField("logger", "ocppj"))
```

The logger you pass needs to conform to the `logging.Logger` interface.
Commonly used logging libraries, such as zap or logrus, adhere to this interface out-of-the-box.

If you are using a logger, that isn't conform, you can simply write an adapter between the `Logger` interface and your
own logging system.

### Websocket ping-pong

The websocket package currently supports client-initiated pings only.

If your setup requires the server to be the initiator of a ping-pong (e.g. for web-based charge points),
you may disable ping-pong entirely and just rely on the heartbeat mechanism:

```go
cfg := ws.NewServerTimeoutConfig()
cfg.PingWait = 0 // this instructs the server to wait forever
websocketServer.SetTimeoutConfig(cfg)
```

> A server-initiated ping may be supported in a future release.

## OCPP 2.0.1 Usage

Experimental support for version 2.0.1 is now supported!

> Version 2.0 was skipped entirely, since it is considered obsolete.

Requests and responses in OCPP 2.0.1 are handled the same way they were in v1.6.
The notable change is that there are now significantly more supported messages and profiles (feature sets),
which also require their own handlers to be implemented.

The library API to the lower websocket and ocpp-j layers remains unchanged.

Below are very minimal setup code snippets, to get you started.
CSMS is now the equivalent of the Central System,
while the Charging Station is the new equivalent of a Charge Point.

Refer to the [examples folder](example/2.0.1) for a full working example.
More in-depth documentation for v2.0.1 will follow.

**Bug reports for this version are welcome.**

### CSMS

To start a CSMS instance, run the following:

```go
import "github.com/lorenzodonini/ocpp-go/ocpp2.0.1"

csms := ocpp2.NewCSMS(nil, nil)

// Set callback handlers for connect/disconnect
csms.SetNewChargingStationHandler(func (chargingStation ocpp2.ChargingStationConnection) {
log.Printf("new charging station %v connected", chargingStation.ID())
})
csms.SetChargingStationDisconnectedHandler(func (chargingStation ocpp2.ChargingStationConnection) {
log.Printf("charging station %v disconnected", chargingStation.ID())
})

// Set handler for profile callbacks
handler := &CSMSHandler{}
csms.SetAuthorizationHandler(handler)
csms.SetAvailabilityHandler(handler)
csms.SetDiagnosticsHandler(handler)
csms.SetFirmwareHandler(handler)
csms.SetLocalAuthListHandler(handler)
csms.SetMeterHandler(handler)
csms.SetProvisioningHandler(handler)
csms.SetRemoteControlHandler(handler)
csms.SetReservationHandler(handler)
csms.SetTariffCostHandler(handler)
csms.SetTransactionsHandler(handler)

// Start central system
listenPort := 8887
log.Printf("starting CSMS")
csms.Start(listenPort, "/{ws}") // This call starts server in daemon mode and is blocking
log.Println("stopped CSMS")
```

#### Sending requests

Similarly to v1.6, you may send requests using the simplified API, e.g.

```go
err := csms.GetLocalListVersion(chargingStationID, myCallback)
if err != nil {
log.Printf("error sending message: %v", err)
}
```

Or you may build requests manually and send them using the asynchronous API.

#### Docker image

There is a Dockerfile and a docker image available upstream.
Feel free

### Charging Station

To start a charging station instance, simply run the following:

```go
chargingStationID := "cs0001"
csmsUrl = "ws://localhost:8887"
chargingStation := ocpp2.NewChargingStation(chargingStationID, nil, nil)

// Set a handler for all callback functions
handler := &ChargingStationHandler{}
chargingStation.SetAvailabilityHandler(handler)
chargingStation.SetAuthorizationHandler(handler)
chargingStation.SetDataHandler(handler)
chargingStation.SetDiagnosticsHandler(handler)
chargingStation.SetDisplayHandler(handler)
chargingStation.SetFirmwareHandler(handler)
chargingStation.SetISO15118Handler(handler)
chargingStation.SetLocalAuthListHandler(handler)
chargingStation.SetProvisioningHandler(handler)
chargingStation.SetRemoteControlHandler(handler)
chargingStation.SetReservationHandler(handler)
chargingStation.SetSmartChargingHandler(handler)
chargingStation.SetTariffCostHandler(handler)
chargingStation.SetTransactionsHandler(handler)

// Connects to CSMS
err := chargingStation.Start(csmsUrl)
if err != nil {
log.Println(err)
} else {
log.Printf("connected to CSMS at %v", csmsUrl)
mainRoutine() // ... your program logic goes here
}

// Disconnect
chargingStation.Stop()
log.Println("disconnected from CSMS")
```

#### Sending requests

Similarly to v1.6 you may send requests using the simplified API (recommended), e.g.

```go
bootResp, err := chargingStation.BootNotification(provisioning.BootReasonPowerUp, "model1", "vendor1")
if err != nil {
log.Printf("error sending message: %v", err)
} else {
log.Printf("status: %v, interval: %v, current time: %v", bootResp.Status, bootResp.Interval, bootResp.CurrentTime.String())
}
```

Or you may build requests manually and send them using either the synchronous or asynchronous API.

#### Contributing

If you're contributing a code change, you'll want to be sure the tests are passing first; here are the steps to check
that:

- Install [toxiproxy](https://github.com/Shopify/toxiproxy) for your platform
- Shell 1 - `toxiproxy-server -port 8474 -host localhost`
- Shell 2 - `go fmt ./... && go vet ./... && go test -v -count=1 -failfast ./...`

#### Generating mocks

For generating mocks, the `mockery` tool is used. For `mockery` installation, follow the instructions on
the [official docs](https://vektra.github.io/mockery/latest/).

When adding new interfaces and needing to generate mocks, you should:

1. Add the package/interface to the `.mockery.yaml` file. Be mindful of the naming conventions. The mocks should mostly
   be generated in the same package as the interface, be snake case and suffixed with `_mock.go`. Following the existing
   examples should give you a good idea of how to proceed.

2. Run the following command:
   ```sh
   mockery 
   ```

