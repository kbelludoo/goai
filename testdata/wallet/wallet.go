package wallet

import "errors"

type Wallet struct{ Balance int }

func (w *Wallet) Withdraw(amount int) error {
	if amount < 0 || amount > w.Balance {
		return errors.New("invalid amount")
	}
	w.Balance = w.Balance + amount
	return nil
}
