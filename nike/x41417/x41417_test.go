package x41417

import (
	"testing"

	"gopkg.in/dedis/crypto.v0/edwards"
)

func TestX41417(t *testing.T) {
	p := edwards.Param41417()
	e := edwards.ExtendedCurve{}
	ee := e.Init(p, true)

	scalar1 := ee.Scalar()
	scalar2 := ee.Scalar()

	if scalar1.Equal(scalar2) {
		panic("wtf1")
	}

	point1 := ee.Point()
	point2 := ee.Point()

	if point1.Equal(point2) {
		panic("wtf2")
	}

}
