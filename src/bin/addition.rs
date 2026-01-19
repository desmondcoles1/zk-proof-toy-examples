use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::thread_rng;
use ark_r1cs_std::alloc::AllocVar;
/*
In this part, before main(), we define our circuit. The circuit is a system of polynmial equations
defined over a finite field. They take public inputs and secret inputs. In this case x and y
are secret, and z is public. The circuit enforces the constraint that x + y = z.
In my next example I want to do one where we commit to z but keep it secret.
*/

/* 
This is our circuit struct, it is effectively just a tuple.
Fr is a field element from the BLS12-381 scalar field.
We use option because we won't actually use fixed values at all times.
*/ 
struct AdditionCircuit {
    x: Option<Fr>,
    y: Option<Fr>,
    z: Option<Fr>,
}

//This just allows us to clone our struct
impl Clone for AdditionCircuit {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for AdditionCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // sets x and y as the secret inputs (aka witnesses)
        let x = FpVar::new_witness(cs.clone(), || self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = FpVar::new_witness(cs.clone(), || self.y.ok_or(SynthesisError::AssignmentMissing))?;
        
        // sets z as public inout
        let z = FpVar::new_input(cs.clone(), || self.z.ok_or(SynthesisError::AssignmentMissing))?;
        
        // this says that they satisfy the constraint x + y =z
        let sum = &x + &y;
        sum.enforce_equal(&z)?;
        
        Ok(())
    }
}

// now we actually run the protocol
fn main() {
    let mut rng = thread_rng();
    

    // we're just defining the circuit here
    let circuit = AdditionCircuit {
        x: None,
        y: None,
        z: None,
    };
    
    //using that definition, we generate the secret key for building a proof and the public key for verifying it.
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
        .expect("Failed to setup");
    println!("✓ Setup complete: generated proving key and verifying key\n");
    
    
    // this fixes the values of x y and z. They are 17, 2 and 19.
    let x = Fr::from(17u32);
    let y = Fr::from(2u32);
    let z = x + y; // z = 18
    
    //println!("Secret x: {}", x);
    //println!("Secret y: {}", y);
    //println!("Public z (x + y): {}", z);
    
    // we put these values into our circuit
    let circuit = AdditionCircuit {
        x: Some(x),
        y: Some(y),
        z: Some(z),
    };
    
    //this builds the proof
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
        .expect("Failed to generate proof");
    println!("✓ Proof generated\n");
    
    // now we can verify the proof
    println!("=== VERIFIER ===");
    let is_valid = Groth16::<Bls12_381>::verify(&vk, &[z], &proof)
        .expect("Failed to verify");
    
    if is_valid {
        println!("  The proof is valid (read that like I'm gen z and on tiktok).");
        println!("  Verifier confirms: you know secrets x and y where x + y = {}", z);
        println!("  The verifier never saw x or y!\n");
    } else {
        println!("Proof is invalid, you messed up, or you lyin' ");
    }
    
    // this is a text that will use the wrong z and it should fail
    println!("=== TESTING WITH WRONG PUBLIC INPUT ===");
    let wrong_z = Fr::from(20u32);
    let is_valid_wrong = Groth16::<Bls12_381>::verify(&vk, &[wrong_z], &proof)
        .expect("Failed to verify");
    
    if !is_valid_wrong {
        println!("Correctly rejected proof with wrong public input (z = {})", wrong_z);
    }
}