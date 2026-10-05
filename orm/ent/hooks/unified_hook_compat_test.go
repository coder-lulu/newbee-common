package hooks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
)

type compatibilityPredicate func(*sql.Selector)
type compatibilityQuery struct{ predicates []compatibilityPredicate }

func (q *compatibilityQuery) Where(p ...compatibilityPredicate) *compatibilityQuery {
	q.predicates = append(q.predicates, p...)
	return q
}

type modifierCompatibilityQuery struct{ modifiers []func(*sql.Selector) }

func compatibilityConfig(required, critical, missing bool) *FieldConfig {
	return &FieldConfig{FieldType: FieldTypeTenant, FieldName: "tenant_id", SetterMethod: "SetTenantID", GetterMethod: "TenantID", RequireValue: required, SecurityCritical: critical,
		ContextExtractor: func(context.Context) (uint64, error) {
			if missing {
				return 0, errors.New("missing tenant")
			}
			return 23, nil
		},
	}
}

func TestUnifiedQueryCompatibilitySQL(t *testing.T) {
	for _, mode := range []string{"where", "modifiers"} {
		for _, missing := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/tenant", true: "/empty"}[missing], func(t *testing.T) {
				m := NewUnifiedHookManager()
				m.RegisterField(compatibilityConfig(false, true, missing))
				var query ent.Query = &compatibilityQuery{}
				if mode == "modifiers" {
					query = &modifierCompatibilityQuery{}
				}
				called := false
				next := ent.QuerierFunc(func(_ context.Context, q ent.Query) (ent.Value, error) {
					called = true
					s := sql.Select("id").From(sql.Table("proxies"))
					switch q := q.(type) {
					case *compatibilityQuery:
						for _, p := range q.predicates {
							p(s)
						}
					case *modifierCompatibilityQuery:
						for _, p := range q.modifiers {
							p(s)
						}
					}
					statement, args := s.Query()
					if missing {
						if !strings.Contains(statement, "WHERE FALSE") || len(args) != 0 {
							t.Fatalf("expected empty-result SQL, got %s %v", statement, args)
						}
					} else if !strings.Contains(statement, "`proxies`.`tenant_id` = ?") || len(args) != 1 || args[0] != uint64(23) {
						t.Fatalf("missing tenant predicate: %s %v", statement, args)
					}
					return nil, nil
				})
				if _, err := m.CreateQueryInterceptor(FieldTypeTenant).Intercept(next).Query(context.Background(), query); err != nil || !called {
					t.Fatalf("query called=%v err=%v", called, err)
				}
			})
		}
	}
}

func TestUnifiedQueryUnsupportedFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		required, critical, missing bool
	}{
		{"required", true, false, false}, {"critical", false, true, false}, {"critical missing", false, true, true}, {"required missing", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewUnifiedHookManager()
			m.RegisterField(compatibilityConfig(tc.required, tc.critical, tc.missing))
			called := false
			next := ent.QuerierFunc(func(context.Context, ent.Query) (ent.Value, error) { called = true; return nil, nil })
			_, err := m.CreateQueryInterceptor(FieldTypeTenant).Intercept(next).Query(context.Background(), &struct{}{})
			if err == nil || called {
				t.Fatalf("unsafe query executed: called=%v err=%v", called, err)
			}
		})
	}
}

type compatibilityMutation struct{ ent.Mutation }

func (*compatibilityMutation) Type() string { return "Proxy" }
func (*compatibilityMutation) Op() ent.Op   { return ent.OpCreate }

type invalidDepartmentMutation struct{ compatibilityMutation }

func (*invalidDepartmentMutation) SetDepartmentID(string) {}

type getterDepartmentMutation struct{ compatibilityMutation }

func (*getterDepartmentMutation) DepartmentID() (uint64, bool) { return 0, false }

func TestUnifiedMutationMissingOptionalField(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		mutation                      ent.Mutation
		required, critical, wantError bool
	}{
		{"optional absent", &compatibilityMutation{}, false, false, false},
		{"required absent", &compatibilityMutation{}, true, false, true},
		{"critical absent", &compatibilityMutation{}, false, true, true},
		{"invalid setter", &invalidDepartmentMutation{}, false, false, true},
		{"getter without setter", &getterDepartmentMutation{}, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewUnifiedHookManager()
			cfg := compatibilityConfig(tc.required, tc.critical, false)
			cfg.FieldType = FieldTypeDepartment
			cfg.FieldName = "department_id"
			cfg.SetterMethod = "SetDepartmentID"
			cfg.GetterMethod = "DepartmentID"
			m.RegisterField(cfg)
			called := false
			next := ent.MutateFunc(func(context.Context, ent.Mutation) (ent.Value, error) { called = true; return nil, nil })
			_, err := m.CreateMutationHook(FieldTypeDepartment)(next).Mutate(context.Background(), tc.mutation)
			if (err != nil) != tc.wantError || called == tc.wantError {
				t.Fatalf("called=%v err=%v wantError=%v", called, err, tc.wantError)
			}
		})
	}
}
