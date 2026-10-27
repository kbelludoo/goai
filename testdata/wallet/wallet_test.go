package wallet

import "testing"

func TestWithdraw(t *testing.T) {
	w := Wallet{Balance: 100}
	if err := w.Withdraw(30); err != nil {
		t.Fatal(err)
	}
	if w.Balance != 70 {
		t.Fatalf("wanted 70, got %d", w.Balance)
	}
}
