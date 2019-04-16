# pwncheck

tests if a given password has been pwned using the haveibeenpwned.com API. 

inspired by the browser + node.js implementation [here](https://github.com/jamiebuilds/havetheybeenpwned). see the [why you should use this](https://github.com/jamiebuilds/havetheybeenpwned#why-you-should-use-this) section from that repo for more info.

## Usage
```golang
import (
  "fmt"
  "github.com/stripedpajamas/pwncheck"
)

func main() {
  pwned, err := pwncheck.Pwned("helloworld")
  if err != nil {
    // errors out if not able to hit API
  }
  fmt.Println(pwned) // true
}
```

## License
MIT